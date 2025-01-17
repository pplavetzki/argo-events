/*
Copyright 2018 BlackRock, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"fmt"
	"github.com/argoproj/argo-events/common"
	gwcommon "github.com/argoproj/argo-events/gateways/common"
	"io/ioutil"
	"net/http"

	"github.com/argoproj/argo-events/gateways"
)

var (
	helper = gwcommon.NewWebhookHelper()
)

func init() {
	go gwcommon.InitRouteChannels(helper)
}

func (rc *RouteConfig) GetRoute() *gwcommon.Route {
	return rc.Route
}

// RouteHandler handles new route
func (rc *RouteConfig) RouteHandler(writer http.ResponseWriter, request *http.Request) {
	var response string

	r := rc.Route

	log := r.Logger.WithFields(
		map[string]interface{}{
			common.LabelEventSource: r.EventSource.Name,
			common.LabelEndpoint:    r.Webhook.Endpoint,
			common.LabelPort:        r.Webhook.Port,
			common.LabelHTTPMethod:  r.Webhook.Method,
		})

	log.Info("request received")

	if !helper.ActiveEndpoints[r.Webhook.Endpoint].Active {
		response = fmt.Sprintf("the route: endpoint %s and method %s is deactived", r.Webhook.Endpoint, r.Webhook.Method)
		log.Info("endpoint is not active")
		common.SendErrorResponse(writer, response)
		return
	}

	if r.Webhook.Method != request.Method {
		log.WithFields(
			map[string]interface{}{
				"expected": r.Webhook.Method,
				"actual":   request.Method,
			},
		).Warn("method mismatch")

		common.SendErrorResponse(writer, fmt.Sprintf("the method %s is not defined for endpoint %s", r.Webhook.Method, r.Webhook.Endpoint))
		return
	}

	if r.Webhook.AuthURL != "" {
		jwt := gwcommon.NewJWTMw(gwcommon.Options{AuthEndpoint: r.Webhook.AuthURL})
		err := jwt.CheckJWT(writer, request)
		if err != nil {
			log.Info("invalid token or auth url")
			response = fmt.Sprintf("the Auth Url %s was invalid or the token proved was invalid %v", r.Webhook.AuthURL, err)
			common.SendErrorResponse(writer, response)
		}
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.WithError(err).Error("failed to parse request body")
		common.SendErrorResponse(writer, fmt.Sprintf("failed to parse request. err: %+v", err))
		return
	}

	helper.ActiveEndpoints[r.Webhook.Endpoint].DataCh <- body
	response = "request successfully processed"
	log.Info(response)
	common.SendSuccessResponse(writer, response)
}

func (rc *RouteConfig) PostStart() error {
	return nil
}

func (rc *RouteConfig) PostStop() error {
	return nil
}

// StartEventSource starts a event source
func (ese *WebhookEventSourceExecutor) StartEventSource(eventSource *gateways.EventSource, eventStream gateways.Eventing_StartEventSourceServer) error {
	defer gateways.Recover(eventSource.Name)

	log := ese.Log.WithField(common.LabelEventSource, eventSource.Name)

	log.Info("operating on event source")
	config, err := parseEventSource(eventSource.Data)
	if err != nil {
		log.WithError(err).Error("failed to parse event source")
		return err
	}
	h := config.(*gwcommon.Webhook)
	h.Endpoint = gwcommon.FormatWebhookEndpoint(h.Endpoint)

	return gwcommon.ProcessRoute(&RouteConfig{
		Route: &gwcommon.Route{
			Logger:      ese.Log,
			EventSource: eventSource,
			StartCh:     make(chan struct{}),
			Webhook:     h,
		},
	}, helper, eventStream)
}
