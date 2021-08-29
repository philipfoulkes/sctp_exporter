// Copyright 2021 Philip Foulkes
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"github.com/philipfoulkes/sctp_exporter/sctp"
	"gopkg.in/alecthomas/kingpin.v2"
	"net/http"
	"os"
)

var (
	listenAddress = kingpin.Flag(
		"web.listen-address",
		"Address on which to expose metrics and web interface.",
	).Default(":9851").String()
	metricsPath = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Default("/metrics").String()
	maxRequests = kingpin.Flag(
		"web.max-requests",
		"Maximum number of parallel scrape requests. Use 0 to disable.",
	).Default("40").Int()
)

func main() {

	kingpin.Parse()

	collector, err := sctp.NewCollector(*maxRequests)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, fmt.Errorf("failed to create new exporter: %w\n",
			err).Error())
		os.Exit(1)
	}

	http.Handle(*metricsPath, collector)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
			<head><title>SCTP Exporter</title></head>
			<body>
			<h1>SCTP Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})

	httpServer := &http.Server{
		Addr: *listenAddress,
	}

	if err := httpServer.ListenAndServe(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, fmt.Errorf("http server terminated: %w\n",
			err).Error())
		os.Exit(0)
	}

} // main()
