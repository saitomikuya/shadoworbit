package api

import (
	"net/http"

	"snell-panel/internal/protocol"
)

func (s *server) handlePublicStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	snap, err := s.hub.BuildPublicSnapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build public status")
		return
	}
	if snap.Nodes == nil {
		snap.Nodes = []protocol.PublicNodeView{}
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *server) handlePublicWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.hub.ServePublicWS(w, r)
}

func (s *server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.hub.ServeAgentWS(w, r)
}
