package controller

import (
	"bytes"
	"net/http"

	"github.com/rs/zerolog/log"
)

func makePostCall(url string, body []byte) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("failed to create new request")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	_, err = client.Do(req)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("error in call")
		return
	}
}

func respOK(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	if len(body) == 0 {
		return
	}
	if _, err := w.Write(body); err != nil {
		log.Error().Err(err).Msg("failed to write response body")
	}
}

func respBadRequest(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
}

func respInternalError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
}
