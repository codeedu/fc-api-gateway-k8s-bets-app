package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/motemen/go-loghttp"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var log *zerolog.Logger
var tracer = otel.Tracer("echo-server")
var httpClient *http.Client

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	logger := zerolog.New(output).With().Timestamp().Caller().Logger()
	log = &logger
	transport := &loghttp.Transport{
		LogRequest: func(req *http.Request) {
			log.Debug().
				Interface("headers", req.Header).
				Msg("calling " + req.Method + " " + req.URL.String())
		},
		LogResponse: func(res *http.Response) {
			req := res.Request
			log.Debug().
				Str("status", res.Status).
				Interface("headers", res.Header).
				Msg("call " + req.Method + " " + req.URL.String() + " answered")
		},
	}
	httpClient = &http.Client{Transport: otelhttp.NewTransport(transport)}
}

func initTracer() (*sdktrace.TracerProvider, error) {
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(os.Getenv("JAEGER_API"))))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		// Always be sure to batch in production.
		sdktrace.WithBatcher(exp),
		// Record information about this application in a Resource.
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("bet"),
		)),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}, b3.New()))
	return tp, nil
}

func main() {
	start := time.Now()
	e := echo.New()
	e.Logger.SetOutput(ioutil.Discard)
	// Middleware
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			req := c.Request()
			res := c.Response()
			start := time.Now()
			log.Debug().
				Interface("headers", req.Header).
				Msg(">>> " + req.Method + " " + req.RequestURI)
			if err = next(c); err != nil {
				c.Error(err)
			}
			log.Debug().
				Str("latency", time.Now().Sub(start).String()).
				Int("status", res.Status).
				Interface("headers", res.Header()).
				Msg("<<< " + req.Method + " " + req.RequestURI)
			return
		}
	})
	e.Use(middleware.Recover())
	//CORS
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.HEAD, echo.PUT, echo.PATCH, echo.POST, echo.DELETE},
	}))

	e.Static("/static", "assets/api-docs")

	tp, err := initTracer()
	if err != nil {
		log.Panic()
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Printf("Error shutting down tracer provider: %v", err)
		}
	}()

	skipper := otelecho.WithSkipper(func(c echo.Context) bool {
		return !strings.Contains(c.Request().RequestURI, "/health")
	})

	e.Use(otelecho.Middleware("bet", skipper))
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		ctx := c.Request().Context()
		oteltrace.SpanFromContext(ctx).RecordError(err)
		e.DefaultHTTPErrorHandler(err, c)
	}

	// Server
	e.POST("/api/bets", CreateBet)
	e.GET("/health", Health)
	elapsed := time.Now().Sub(start)
	log.Debug().Msg("Bets app initialized in " + elapsed.String())
	e.Logger.Fatal(e.Start(":9999"))
}

func Health(c echo.Context) error {
	return c.JSON(200, &HealthData{Status: "UP"})
}

type HealthData struct {
	Status string `json:"status,omitempty"`
}

func CreateBet(c echo.Context) error {
	defer c.Request().Body.Close()
	bet := &Bet{}
	if err := json.NewDecoder(c.Request().Body).Decode(bet); err != nil {
		log.Error().Err(err).Msg("Failed reading the request body")
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error)
	}

	match, matchStatus, matchErr := match(c)
	player, playerStatus, playerErr := player(c)
	champ, champStatus, champErr := championship(c)

	if hasError(matchErr, playerErr, champErr) {
		return c.JSON(http.StatusServiceUnavailable, &Error{Errors: map[string]int{
			"players":       playerStatus,
			"matches":       matchStatus,
			"championships": champStatus,
		}})
	}

	b := &Bet{
		HomeTeamScore: strconv.Itoa(2),
		AwayTeamScore: strconv.Itoa(3),
		Championship:  champ,
		Match:         match.String(),
		Email:         player,
	}
	return c.JSON(http.StatusCreated, b)
}

func hasError(errs ...error) bool {
	r := false
	for _, err := range errs {
		if err != nil {
			r = true
		}
	}
	return r
}

func match(ctx echo.Context) (*Match, int, error) {
	req, _ := http.NewRequest("GET", os.Getenv("MATCH_SVC"), nil)
	forwardHeaders(ctx, req)
	res, err := httpClient.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("failed to call matches")
		return nil, 0, err
	}
	status := res.StatusCode
	if !is2xx(status) {
		return nil, status, errors.New(res.Status)
	}
	data := &Match{}
	if jsonErr := json.NewDecoder(res.Body).Decode(data); jsonErr != nil {
		log.Error().Err(jsonErr).Msg("failed to read matches response body")
		return nil, 0, jsonErr
	}

	return data, status, nil
}

func forwardHeaders(ctx echo.Context, r *http.Request) {
	incomingHeaders := []string{
		"Authorization",
		"x-version",

		// open tracing
		"x-request-id",
		"x-b3-traceid",
		"x-b3-spanid",
		"x-b3-parentspanid",
		"x-b3-sampled",
		"x-b3-flags",

		// open telemetry
		"ot-tracer-spanid",
		"ot-tracer-traceid",
		"ot-tracer-sampled",
	}
	for _, th := range incomingHeaders {
		h := ctx.Request().Header.Get(th)
		if h != "" {
			r.Header.Set(th, h)
		}
	}
}

func championship(ctx echo.Context) (string, int, error) {
	req, _ := http.NewRequest("GET", os.Getenv("CHAMPIONSHIP_SVC"), nil)
	forwardHeaders(ctx, req)
	res, err := httpClient.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("failed to call championships")
		return "", 0, err
	}
	status := res.StatusCode
	if !is2xx(status) {
		return "", status, errors.New(res.Status)
	}
	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Error().Err(err).Msg("failed to read matches response body")
		return "", status, readErr
	}

	var data map[string]string

	if jsonErr := json.Unmarshal(body, &data); jsonErr != nil {
		log.Error().Err(err).Msg("failed to read matches response body")
		return "", status, jsonErr
	}
	return data["title"], status, nil
}

func player(ctx echo.Context) (string, int, error) {
	req, _ := http.NewRequest("GET", os.Getenv("PLAYER_SVC"), nil)
	forwardHeaders(ctx, req)
	res, err := httpClient.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("failed to call players")
		return "", 0, err
	}
	status := res.StatusCode
	if !is2xx(status) {
		return "", status, errors.New(res.Status)
	}
	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Error().Err(err).Msg("failed to read players response body")
		return "", status, readErr
	}

	var data map[string]string

	if jsonErr := json.Unmarshal(body, &data); jsonErr != nil {
		log.Error().Err(err).Msg("failed to read players response body")
		return "", status, jsonErr
	}
	return data["email"], status, nil
}

func is2xx(status int) bool {
	return status >= 200 && status < 300
}

type Bet struct {
	HomeTeamScore string `json:"homeTeamScore,omitempty"`
	AwayTeamScore string `json:"awayTeamScore,omitempty"`
	Championship  string `json:"championship,omitempty"`
	Match         string `json:"match,omitempty"`
	Email         string `json:"email,omitempty"`
}

type Error struct {
	Errors map[string]int `json:"errors,omitempty"`
}

type Match struct {
	Date         time.Time `json:"date"`
	Championship string    `json:"championship"`
	Teams        struct {
		Home struct {
			Name  string `json:"name"`
			Score int    `json:"score"`
		} `json:"home"`
		Away struct {
			Name  string `json:"name"`
			Score int    `json:"score"`
		} `json:"Away"`
	} `json:"teams"`
}

func (m *Match) String() string {
	h := m.Teams.Home
	a := m.Teams.Away
	return fmt.Sprintf("%s - %s %dx%d %s (%s)", m.Date.Format("2006-01-02"), h.Name, h.Score, a.Score, a.Name, m.Championship)
}
