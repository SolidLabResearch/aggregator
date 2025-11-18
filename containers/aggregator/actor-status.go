package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Event struct {
	Type    string      `json:"type"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type EventHub struct {
	subscribers map[string][]chan Event
	lastEvent   map[string]Event
	mu          sync.Mutex
}

func NewEventHub() *EventHub {
	return &EventHub{
		subscribers: make(map[string][]chan Event),
		lastEvent:   make(map[string]Event),
	}
}

// Subscribe registers a new listener for an actor’s events and immediately
// sends the last known event (if any).
func (h *EventHub) Subscribe(actorID string) <-chan Event {
	h.mu.Lock()
	defer h.mu.Unlock()

	ch := make(chan Event, 10)
	h.subscribers[actorID] = append(h.subscribers[actorID], ch)

	// Immediately send the last event if it exists
	if last, ok := h.lastEvent[actorID]; ok {
		ch <- last
	}

	return ch
}

// Publish sends a new event to all subscribers and stores it as the latest event.
func (h *EventHub) Publish(actorID string, event Event) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastEvent[actorID] = event
	for _, ch := range h.subscribers[actorID] {
		select {
		case ch <- event:
		default:
			// Drop if subscriber is slow
		}
	}
}

func (h *EventHub) Unsubscribe(actorID string, ch <-chan Event) {
	h.mu.Lock()
	defer h.mu.Unlock()

	subs := h.subscribers[actorID]
	for i, c := range subs {
		if c == ch {
			h.subscribers[actorID] = append(subs[:i], subs[i+1:]...)
			close(c)
			break
		}
	}

	if len(h.subscribers[actorID]) == 0 {
		delete(h.subscribers, actorID)
	}
}

func (h *EventHub) WatchActorDeployments(actor *Actor) {
	go func() {
		ctx := context.Background()

		h.Publish(actor.id, Event{Type: "info", Message: "Watching deployments for readiness..."})

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				h.Publish(actor.id, Event{Type: "info", Message: "Stopped watching actor deployments"})
				return
			case <-ticker.C:
				allReady := true
				for _, d := range actor.deployments {
					dep, err := Clientset.AppsV1().Deployments(actor.namespace).Get(ctx, d.Name, metav1.GetOptions{})
					if err != nil {
						h.Publish(actor.id, Event{
							Type:    "error",
							Message: fmt.Sprintf("error fetching deployment %s: %v", d.Name, err),
						})
						allReady = false
						continue
					}

					ready := dep.Status.ReadyReplicas == dep.Status.Replicas && dep.Status.Replicas > 0
					progress := fmt.Sprintf("Deployment %s: %d/%d ready", d.Name, dep.Status.ReadyReplicas, dep.Status.Replicas)
					h.Publish(actor.id, Event{
						Type:    "status",
						Message: progress,
						Data: map[string]int32{
							"ready":     dep.Status.ReadyReplicas,
							"replicas":  dep.Status.Replicas,
							"available": dep.Status.AvailableReplicas,
						},
					})

					if !ready {
						allReady = false
					}
				}

				if allReady {
					h.Publish(actor.id, Event{
						Type:    "ready",
						Message: "All deployments are ready",
					})
					return
				}
			}
		}
	}()
}
