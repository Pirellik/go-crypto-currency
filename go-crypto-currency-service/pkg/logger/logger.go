package logger

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

func LoggingInterceptor(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		inner.ServeHTTP(w, r)

		log.Info().
			Str("host", r.Host).
			Str("method", r.Method).
			Str("requestURI", r.RequestURI).
			Dur("responseTime", time.Since(start)).
			Send()
	})
}
