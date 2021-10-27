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

package sctp

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Collector is the SCTP metrics collector
type Collector struct {
	requestsLim chan struct{}
	assoc       struct {
		assocDesc   *prometheus.Desc
		sockDesc    *prometheus.Desc
		styDesc     *prometheus.Desc
		sstDesc     *prometheus.Desc
		stDesc      *prometheus.Desc
		hbktDesc    *prometheus.Desc
		assocId     *prometheus.Desc
		txQueueDesc *prometheus.Desc
		rxQueueDesc *prometheus.Desc
		uidDesc     *prometheus.Desc
		inodeDesc   *prometheus.Desc
		hbintDesc   *prometheus.Desc
		insDesc     *prometheus.Desc
		outsDesc    *prometheus.Desc
		maxRTDesc   *prometheus.Desc
		t1XDesc     *prometheus.Desc
		t2XDesc     *prometheus.Desc
		rtxcDesc    *prometheus.Desc
		wMemADesc   *prometheus.Desc
		wMemQDesc   *prometheus.Desc
		sndBufDesc  *prometheus.Desc
		rcvBufDesc  *prometheus.Desc
	} // assoc
	ep struct {
		endptDesc *prometheus.Desc
		sockDesc  *prometheus.Desc
		styDesc   *prometheus.Desc
		sstDesc   *prometheus.Desc
		hbktDesc  *prometheus.Desc
		infoDesc  *prometheus.Desc
	} // ep
	remAddr struct {
		hbActDesc      *prometheus.Desc
		rtoDesc        *prometheus.Desc
		maxPathRtxDesc *prometheus.Desc
		remAddrRtxDesc *prometheus.Desc
		startDesc      *prometheus.Desc
		stateDesc      *prometheus.Desc
	} // remAddr
	snmp struct {
		currEstabDesc               *prometheus.Desc
		activeEstabsDesc            *prometheus.Desc
		passiveEstabsDesc           *prometheus.Desc
		abortedsDesc                *prometheus.Desc
		shutdownsDesc               *prometheus.Desc
		outOfBluesDesc              *prometheus.Desc
		checksumErrorsDesc          *prometheus.Desc
		outCtrlChunksDesc           *prometheus.Desc
		outOrderChunksDesc          *prometheus.Desc
		outUnorderChunksDesc        *prometheus.Desc
		inCtrlChunksDesc            *prometheus.Desc
		inOrderChunksDesc           *prometheus.Desc
		inUnorderChunksDesc         *prometheus.Desc
		fragUsrMsgsDesc             *prometheus.Desc
		reasmUsrMsgsDesc            *prometheus.Desc
		outSCTPPacksDesc            *prometheus.Desc
		inSCTPPacksDesc             *prometheus.Desc
		t1InitExpiredsDesc          *prometheus.Desc
		t1CookieExpiredsDesc        *prometheus.Desc
		t2ShutdownExpiredsDesc      *prometheus.Desc
		t3RtxExpiredsDesc           *prometheus.Desc
		t4RtoExpiredsDesc           *prometheus.Desc
		t5ShutdownGuardExpiredsDesc *prometheus.Desc
		delaySackExpiredsDesc       *prometheus.Desc
		autoCloseExpiredsDesc       *prometheus.Desc
		t3RetransmitsDesc           *prometheus.Desc
		pmtudRetransmitsDesc        *prometheus.Desc
		fastRetransmitsDesc         *prometheus.Desc
		inPktSoftIRQDesc            *prometheus.Desc
		inPktBacklogDesc            *prometheus.Desc
		inPktDiscardsDesc           *prometheus.Desc
		inDataChunkDiscardsDesc     *prometheus.Desc
	} // snmp
} // Collector

type assoc struct {
	assoc   uint64
	sock    uint64
	sty     int64
	sst     int64
	st      int64
	hbkt    int64
	assocId int64
	txQueue int64
	rxQueue int64
	uid     int64
	inode   int64
	lPort   int64
	rPort   int64
	lAddrs  string
	rAddrs  string
	hbint   int64
	ins     int64
	outs    int64
	maxRT   int64
	t1x     int64
	t2x     int64
	rtxc    int64
	wmema   int64
	wmemq   int64
	sndBuf  int64
	rcvBuf  int64
} // assoc

type ep struct {
	endpt  int64
	sock   int64
	sty    int64
	sst    int64
	hbkt   int64
	lPort  int64
	uid    int64
	inode  int64
	lAddrs string
} // ep

type remAddr struct {
	addr       string
	assocId    int64
	hbAct      int64
	rto        int64
	maxPathRtx int64
	remAddrRtx int64
	start      int64
	state      int64
} // remAddr

type snmp struct {
	currEstab               int64
	activeEstabs            int64
	passiveEstabs           int64
	aborteds                int64
	shutdowns               int64
	outOfBlues              int64
	checksumErrors          int64
	outCtrlChunks           int64
	outOrderChunks          int64
	outUnorderChunks        int64
	inCtrlChunks            int64
	inOrderChunks           int64
	inUnorderChunks         int64
	fragUsrMsgs             int64
	reasmUsrMsgs            int64
	outSCTPPacks            int64
	inSCTPPacks             int64
	t1InitExpireds          int64
	t1CookieExpireds        int64
	t2ShutdownExpireds      int64
	t3RtxExpireds           int64
	t4RtoExpireds           int64
	t5ShutdownGuardExpireds int64
	delaySackExpireds       int64
	autocloseExpireds       int64
	t3Retransmits           int64
	pmtudRetransmits        int64
	fastRetransmits         int64
	inPktSoftirq            int64
	inPktBacklog            int64
	inPktDiscards           int64
	inDataChunkDiscards     int64
} // snmp

var (
	collector     Collector
	collectorOnce sync.Once
)

// NewCollector returns the SCTP collector. If it has not been created yet, it
// will create it
func NewCollector(maxRequests int) (*Collector, error) {

	var err error

	collectorOnce.Do(func() {
		if e := collector.init(maxRequests); e != nil {
			err = fmt.Errorf("failed to initialise collector: %w",
				e)
		}
	})

	if err != nil {
		return nil, fmt.Errorf("failed to initialise collector: %w",
			err)
	}

	return &collector, nil

} // NewCollector()

// init initialises the SCTP collector
func (collector *Collector) init(maxRequests int) error {

	if collector == nil {
		return fmt.Errorf("invalid parameters")
	}

	if maxRequests > 0 {
		collector.requestsLim = make(chan struct{}, maxRequests)
	}

	{
		const namespace = "sctp"
		const subsystem = "assoc"
		commonLabels := []string{"local_port", "remote_port", "local_addresses", "remote_addresses"}

		collector.assoc.assocDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "association_pointer"),
			"Association pointer",
			commonLabels,
			nil)

		collector.assoc.sockDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "socket_pointer"),
			"Socket pointer",
			commonLabels,
			nil)

		collector.assoc.styDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "socket_style"),
			"Socket style",
			commonLabels,
			nil)

		collector.assoc.sstDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "socket_state"),
			"Socket state",
			commonLabels,
			nil)

		collector.assoc.stDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "association_state"),
			"Association state",
			commonLabels,
			nil)

		collector.assoc.hbktDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "hash_bucket"),
			"Hash bucket",
			commonLabels,
			nil)

		collector.assoc.assocId = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "association_id"),
			"Association ID",
			commonLabels,
			nil)

		collector.assoc.txQueueDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "transmit_queue_bytes"),
			"Bytes in transmit queue",
			commonLabels,
			nil)

		collector.assoc.rxQueueDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "receive_queue_bytes"),
			"Bytes in receive queue",
			commonLabels,
			nil)

		collector.assoc.uidDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "uid"),
			"UID",
			commonLabels,
			nil)

		collector.assoc.inodeDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "inode"),
			"inode",
			commonLabels,
			nil)

		collector.assoc.hbintDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "heartbeat_interval_seconds"),
			"Heartbeat interval",
			commonLabels,
			nil)

		collector.assoc.insDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "in_streams"),
			"Max in streams",
			commonLabels,
			nil)

		collector.assoc.outsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "out_streams"),
			"Max out streams",
			commonLabels,
			nil)

		collector.assoc.maxRTDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "max_retransmissions"),
			"Max retransmissions",
			commonLabels,
			nil)

		collector.assoc.t1XDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "init_retries_total"),
			"Init retries",
			commonLabels,
			nil)

		collector.assoc.t2XDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "shutdown_retries_total"),
			"Shutdown retries",
			commonLabels,
			nil)

		collector.assoc.rtxcDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "retransmit_data_chunks_total"),
			"The total number of data chunks retransmitted as the result of a T3 timer expiration",
			commonLabels,
			nil)

		collector.assoc.wMemADesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "wmema_bytes"),
			"Transmit queue bytes committed",
			commonLabels,
			nil)

		collector.assoc.wMemQDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "wmemq_bytes"),
			"Persistent queue size",
			commonLabels,
			nil)

		collector.assoc.sndBufDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "send_buffer_bytes"),
			"Size of send buffer in bytes",
			commonLabels,
			nil)

		collector.assoc.rcvBufDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "receive_buffer_bytes"),
			"Size of receive buffer in bytes",
			commonLabels,
			nil)

	} // scope assoc

	{
		const namespace = "sctp"
		const subsystem = "ep"
		commonLabels := []string{"local_addresses", "local_port"}

		collector.ep.endptDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "endpoint_pointer"),
			"Endpoint pointer",
			commonLabels,
			nil)

		collector.ep.sockDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "socket_pointer"),
			"Socket pointer",
			commonLabels,
			nil)

		collector.ep.styDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "socket_style"),
			"Socket style",
			commonLabels,
			nil)

		collector.ep.sstDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "socket_state"),
			"Socket state",
			commonLabels,
			nil)

		collector.ep.hbktDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "hash_bucket"),
			"Hash bucket",
			commonLabels,
			nil)

		collector.ep.infoDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "info"),
			"Hash bucket",
			append(commonLabels, []string{"uid", "inode"}...),
			nil)

	} // scope ep

	{
		const namespace = "sctp"
		const subsystem = "remaddr"
		commonLabels := []string{"address", "association_id"}

		collector.remAddr.hbActDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "heartbeat_active"),
			"Heartbeat active",
			commonLabels,
			nil)

		collector.remAddr.rtoDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "retransmission_timeout"),
			"Retransmission timeout",
			commonLabels,
			nil)

		collector.remAddr.maxPathRtxDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "max_path_retransmit_total"),
			"Max path retransmit total",
			commonLabels,
			nil)

		collector.remAddr.remAddrRtxDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "retransmit_total"),
			"Retransmit total",
			commonLabels,
			nil)

		collector.remAddr.startDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "start_time"),
			"Start time",
			commonLabels,
			nil)

		collector.remAddr.stateDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "state"),
			"The current state of this destination",
			commonLabels,
			nil)

	} // scope remaddr

	{
		const namespace = "sctp"
		const subsystem = "snmp"
		commonLabels := []string{}

		collector.snmp.currEstabDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "current_established"),
			"The number of associations for which the current state is either ESTABLISHED, SHUTDOWN-RECEIVED or SHUTDOWN-PENDING",
			commonLabels,
			nil)

		collector.snmp.activeEstabsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "active_established_total"),
			"The number of times that associations have made a direct transition to the ESTABLISHED state from the COOKIE-ECHOED state. The upper layer initiated the association attempt.",
			commonLabels,
			nil)

		collector.snmp.passiveEstabsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "passive_established_total"),
			"The number of times that associations have made a direct transition to the ESTABLISHED state from the CLOSED state. The remote endpoint initiated the association attempt.",
			commonLabels,
			nil)

		collector.snmp.abortedsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "aborted_total"),
			"The number of times that associations have made a direct transition to the CLOSED state from any state using the primitive 'ABORT'. Ungraceful termination of the association.",
			commonLabels,
			nil)

		collector.snmp.shutdownsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "shutdown_total"),
			"The number of times that associations have made a direct transition to the CLOSED state from either the SHUTDOWN-SENT state or the SHUTDOWN-ACK-SENT state. Graceful termination of the association.",
			commonLabels,
			nil)

		collector.snmp.outOfBluesDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "out_of_blue_total"),
			"The number of out of the blue packets received by the host. An out of the blue packet is an SCTP packet correctly formed, including the proper checksum, but for which the receiver was unable to identify an appropriate association.",
			commonLabels,
			nil)

		collector.snmp.checksumErrorsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "checksum_error_total"),
			"The number of SCTP packets received with an invalid checksum.",
			commonLabels,
			nil)

		collector.snmp.outCtrlChunksDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "out_control_chunks_total"),
			"The number of SCTP control chunks sent (retransmissions are not included). Control chunks are those chunks different from DATA.",
			commonLabels,
			nil)

		collector.snmp.outOrderChunksDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "out_ordered_chunks_total"),
			"The number of SCTP ordered data chunks sent (retransmissions are not included).",
			commonLabels,
			nil)

		collector.snmp.outUnorderChunksDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "out_unordered_chunks_total"),
			"The number of SCTP unordered chunks(data chunks in which the U bit is set to 1) sent (retransmissions are not included).",
			commonLabels,
			nil)

		collector.snmp.inCtrlChunksDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "in_control_chunks_total"),
			"The number of SCTP control chunks received (no duplicate chunks included).",
			commonLabels,
			nil)

		collector.snmp.inOrderChunksDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "in_ordered_chunks_total"),
			"The number of SCTP ordered data chunks received (no duplicate chunks included).",
			commonLabels,
			nil)

		collector.snmp.inUnorderChunksDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "in_unordered_chunks_total"),
			"The number of SCTP unordered chunks(data chunks in which the U bit is set to 1) received (no duplicate chunks included).",
			commonLabels,
			nil)

		collector.snmp.fragUsrMsgsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "fragmented_user_messages_total"),
			"The number of user messages that have to be fragmented because of the MTU.",
			commonLabels,
			nil)

		collector.snmp.reasmUsrMsgsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "reassembled_user_messages_total"),
			"The number of user messages reassembled, after conversion into DATA chunks.",
			commonLabels,
			nil)

		collector.snmp.outSCTPPacksDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "out_sctp_packets_total"),
			"The number of SCTP packets sent. Retransmitted DATA chunks are included.",
			commonLabels,
			nil)

		collector.snmp.inSCTPPacksDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "in_sctp_packets_total"),
			"The number of SCTP packets received. Duplicates are included.",
			commonLabels,
			nil)

		collector.snmp.t1InitExpiredsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "t1_init_expired_total"),
			"The number of T1-init expired",
			commonLabels,
			nil)

		collector.snmp.t1CookieExpiredsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "t1_cookie_expired_total"),
			"The number of T1-cookie expired",
			commonLabels,
			nil)

		collector.snmp.t2ShutdownExpiredsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "t2_shutdown_expired_total"),
			"The number of T2-shutdown expired",
			commonLabels,
			nil)

		collector.snmp.t3RtxExpiredsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "t3_retransmission_expired_total"),
			"The number of T3-retransmission expired",
			commonLabels,
			nil)

		collector.snmp.t4RtoExpiredsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "t4_retransmission_timeout_expired_total"),
			"The number of T4-retransmission timeout expired",
			commonLabels,
			nil)

		collector.snmp.t5ShutdownGuardExpiredsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "t5_shutdown_guard_expired_total"),
			"The number of T5 shutdown expired",
			commonLabels,
			nil)

		collector.snmp.delaySackExpiredsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "delayed_sack_expired_total"),
			"The number of delayed SACK expired",
			commonLabels,
			nil)

		collector.snmp.autoCloseExpiredsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "auto_close_expired_total"),
			"The number of auto closed expired",
			commonLabels,
			nil)

		collector.snmp.t3RetransmitsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "t3_retransmit_total"),
			"The number of T3 retransmit",
			commonLabels,
			nil)

		collector.snmp.pmtudRetransmitsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "pmtu_retransmits_total"),
			"The number of PMTU retransmits total",
			commonLabels,
			nil)

		collector.snmp.fastRetransmitsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "fast_retransmits_total"),
			"The number of fast retransmits",
			commonLabels,
			nil)

		collector.snmp.inPktSoftIRQDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "in_packet_soft_irq_total"),
			"The number of in packet soft IRQ",
			commonLabels,
			nil)

		collector.snmp.inPktBacklogDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "in_packet_backlog_total"),
			"In packet backlog",
			commonLabels,
			nil)

		collector.snmp.inPktDiscardsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "in_packet_discard_total"),
			"The number of in packet discards",
			commonLabels,
			nil)

		collector.snmp.inDataChunkDiscardsDesc = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "in_data_chunk_discards_total"),
			"The number of in data chunk discards",
			commonLabels,
			nil)

	} // scope snmp

	if err := prometheus.Register(collector); err != nil {
		return fmt.Errorf("failed to register collector: %w",
			err)
	}

	return nil

} // Collector.init()

// ServeHTTP implements http.Handler
func (collector *Collector) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	if collector == nil {
		return
	}

	if collector.requestsLim != nil {
		select {
		case collector.requestsLim <- struct{}{}:
			defer func() { <-collector.requestsLim }()
		default:
			return
		}
	}

	promhttp.Handler().ServeHTTP(rw, req)

} // Collector.ServeHTTP()

// Describe implements the prometheus.Collector interface
func (collector *Collector) Describe(ch chan<- *prometheus.Desc) {

	if collector == nil {
		return
	}

	// assoc
	ch <- collector.assoc.assocDesc
	ch <- collector.assoc.sockDesc
	ch <- collector.assoc.styDesc
	ch <- collector.assoc.sstDesc
	ch <- collector.assoc.stDesc
	ch <- collector.assoc.hbktDesc
	ch <- collector.assoc.assocId
	ch <- collector.assoc.txQueueDesc
	ch <- collector.assoc.rxQueueDesc
	ch <- collector.assoc.uidDesc
	ch <- collector.assoc.inodeDesc
	ch <- collector.assoc.hbintDesc
	ch <- collector.assoc.insDesc
	ch <- collector.assoc.outsDesc
	ch <- collector.assoc.maxRTDesc
	ch <- collector.assoc.t1XDesc
	ch <- collector.assoc.t2XDesc
	ch <- collector.assoc.rtxcDesc
	ch <- collector.assoc.wMemADesc
	ch <- collector.assoc.wMemQDesc
	ch <- collector.assoc.sndBufDesc
	ch <- collector.assoc.rcvBufDesc

	// ep
	ch <- collector.ep.endptDesc
	ch <- collector.ep.sockDesc
	ch <- collector.ep.styDesc
	ch <- collector.ep.sstDesc
	ch <- collector.ep.hbktDesc
	ch <- collector.ep.infoDesc

	// remaddr
	ch <- collector.remAddr.hbActDesc
	ch <- collector.remAddr.rtoDesc
	ch <- collector.remAddr.maxPathRtxDesc
	ch <- collector.remAddr.remAddrRtxDesc
	ch <- collector.remAddr.startDesc
	ch <- collector.remAddr.stateDesc

	// snmp
	ch <- collector.snmp.currEstabDesc
	ch <- collector.snmp.activeEstabsDesc
	ch <- collector.snmp.passiveEstabsDesc
	ch <- collector.snmp.abortedsDesc
	ch <- collector.snmp.shutdownsDesc
	ch <- collector.snmp.outOfBluesDesc
	ch <- collector.snmp.checksumErrorsDesc
	ch <- collector.snmp.outCtrlChunksDesc
	ch <- collector.snmp.outOrderChunksDesc
	ch <- collector.snmp.outUnorderChunksDesc
	ch <- collector.snmp.inCtrlChunksDesc
	ch <- collector.snmp.inOrderChunksDesc
	ch <- collector.snmp.inUnorderChunksDesc
	ch <- collector.snmp.fragUsrMsgsDesc
	ch <- collector.snmp.reasmUsrMsgsDesc
	ch <- collector.snmp.outSCTPPacksDesc
	ch <- collector.snmp.inSCTPPacksDesc
	ch <- collector.snmp.t1InitExpiredsDesc
	ch <- collector.snmp.t1CookieExpiredsDesc
	ch <- collector.snmp.t2ShutdownExpiredsDesc
	ch <- collector.snmp.t3RtxExpiredsDesc
	ch <- collector.snmp.t4RtoExpiredsDesc
	ch <- collector.snmp.t5ShutdownGuardExpiredsDesc
	ch <- collector.snmp.delaySackExpiredsDesc
	ch <- collector.snmp.autoCloseExpiredsDesc
	ch <- collector.snmp.t3RetransmitsDesc
	ch <- collector.snmp.pmtudRetransmitsDesc
	ch <- collector.snmp.fastRetransmitsDesc
	ch <- collector.snmp.inPktSoftIRQDesc
	ch <- collector.snmp.inPktBacklogDesc
	ch <- collector.snmp.inPktDiscardsDesc
	ch <- collector.snmp.inDataChunkDiscardsDesc

} // Collector.Describe()

// Collect implements the prometheus.Collector interface
func (collector *Collector) Collect(ch chan<- prometheus.Metric) {

	if collector == nil {
		return
	}

	assocs, err := collector.fetchAssocs()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, fmt.Errorf("failed to fetch assocs: %w\n",
			err).Error())
		return
	}

	eps, err := collector.fetchEps()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, fmt.Errorf("failed to fetch eps: %w\n",
			err).Error())
		return
	}

	remAddrs, err := collector.fetchRemAddr()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, fmt.Errorf("failed to fetch remaddr: %w\n",
			err).Error())
		return
	}

	snmp, err := collector.fetchSnmp()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, fmt.Errorf("failed to fetch snmp: %w\n",
			err).Error())
		return
	}

	// assocs
	for _, assoc := range assocs {

		lPort := strconv.FormatInt(assoc.lPort, 10)
		rPort := strconv.FormatInt(assoc.rPort, 10)
		lAddrs := assoc.lAddrs
		rAddrs := assoc.rAddrs

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.assocDesc,
			prometheus.GaugeValue,
			float64(assoc.assoc),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.sockDesc,
			prometheus.GaugeValue,
			float64(assoc.sock),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.styDesc,
			prometheus.GaugeValue,
			float64(assoc.sty),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.sstDesc,
			prometheus.GaugeValue,
			float64(assoc.sst),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.stDesc,
			prometheus.GaugeValue,
			float64(assoc.st),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.hbktDesc,
			prometheus.GaugeValue,
			float64(assoc.hbkt),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.assocId,
			prometheus.GaugeValue,
			float64(assoc.assocId),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.txQueueDesc,
			prometheus.GaugeValue,
			float64(assoc.txQueue),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.rxQueueDesc,
			prometheus.GaugeValue,
			float64(assoc.rxQueue),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.uidDesc,
			prometheus.GaugeValue,
			float64(assoc.uid),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.inodeDesc,
			prometheus.GaugeValue,
			float64(assoc.inode),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.hbintDesc,
			prometheus.GaugeValue,
			float64(assoc.hbint)/1000.00,
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.insDesc,
			prometheus.GaugeValue,
			float64(assoc.ins),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.outsDesc,
			prometheus.GaugeValue,
			float64(assoc.outs),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.maxRTDesc,
			prometheus.GaugeValue,
			float64(assoc.maxRT),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.t1XDesc,
			prometheus.CounterValue,
			float64(assoc.t1x),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.t2XDesc,
			prometheus.CounterValue,
			float64(assoc.t2x),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.rtxcDesc,
			prometheus.CounterValue,
			float64(assoc.rtxc),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.wMemADesc,
			prometheus.GaugeValue,
			float64(assoc.wmema),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.wMemQDesc,
			prometheus.GaugeValue,
			float64(assoc.wmemq),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.sndBufDesc,
			prometheus.GaugeValue,
			float64(assoc.sndBuf),
			lPort, rPort, lAddrs, rAddrs)

		ch <- prometheus.MustNewConstMetric(
			collector.assoc.rcvBufDesc,
			prometheus.GaugeValue,
			float64(assoc.rcvBuf),
			lPort, rPort, lAddrs, rAddrs)

	} // for each assoc

	// eps
	for _, ep := range eps {

		lAddrs := ep.lAddrs
		lPort := strconv.FormatInt(ep.lPort, 10)

		ch <- prometheus.MustNewConstMetric(
			collector.ep.endptDesc,
			prometheus.GaugeValue,
			float64(ep.endpt),
			lAddrs,
			lPort)

		ch <- prometheus.MustNewConstMetric(
			collector.ep.sockDesc,
			prometheus.GaugeValue,
			float64(ep.sock),
			lAddrs,
			lPort)

		ch <- prometheus.MustNewConstMetric(
			collector.ep.styDesc,
			prometheus.GaugeValue,
			float64(ep.sty),
			lAddrs,
			lPort)

		ch <- prometheus.MustNewConstMetric(
			collector.ep.sstDesc,
			prometheus.GaugeValue,
			float64(ep.sst),
			lAddrs,
			lPort)

		ch <- prometheus.MustNewConstMetric(
			collector.ep.hbktDesc,
			prometheus.GaugeValue,
			float64(ep.hbkt),
			lAddrs,
			lPort)

		ch <- prometheus.MustNewConstMetric(
			collector.ep.infoDesc,
			prometheus.GaugeValue,
			0.0,
			lAddrs,
			lPort,
			strconv.FormatInt(ep.uid, 10),
			strconv.FormatInt(ep.inode, 10))

	} // for each ep

	// remaddr
	for _, remAddr := range remAddrs {

		assocId := strconv.FormatInt(remAddr.assocId, 10)

		ch <- prometheus.MustNewConstMetric(
			collector.remAddr.hbActDesc,
			prometheus.GaugeValue,
			float64(remAddr.hbAct),
			remAddr.addr,
			assocId)

		ch <- prometheus.MustNewConstMetric(
			collector.remAddr.rtoDesc,
			prometheus.GaugeValue,
			float64(remAddr.rto),
			remAddr.addr,
			assocId)

		ch <- prometheus.MustNewConstMetric(
			collector.remAddr.maxPathRtxDesc,
			prometheus.GaugeValue,
			float64(remAddr.maxPathRtx),
			remAddr.addr,
			assocId)

		ch <- prometheus.MustNewConstMetric(
			collector.remAddr.remAddrRtxDesc,
			prometheus.GaugeValue,
			float64(remAddr.remAddrRtx),
			remAddr.addr,
			assocId)

		ch <- prometheus.MustNewConstMetric(
			collector.remAddr.startDesc,
			prometheus.GaugeValue,
			float64(remAddr.start),
			remAddr.addr,
			assocId)

		ch <- prometheus.MustNewConstMetric(
			collector.remAddr.stateDesc,
			prometheus.GaugeValue,
			float64(remAddr.state),
			remAddr.addr,
			assocId)

	} // for each remaddr

	// snmp
	ch <- prometheus.MustNewConstMetric(
		collector.snmp.currEstabDesc,
		prometheus.GaugeValue,
		float64(snmp.currEstab))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.activeEstabsDesc,
		prometheus.CounterValue,
		float64(snmp.activeEstabs))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.passiveEstabsDesc,
		prometheus.CounterValue,
		float64(snmp.passiveEstabs))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.abortedsDesc,
		prometheus.CounterValue,
		float64(snmp.aborteds))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.shutdownsDesc,
		prometheus.CounterValue,
		float64(snmp.shutdowns))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.outOfBluesDesc,
		prometheus.CounterValue,
		float64(snmp.outOfBlues))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.checksumErrorsDesc,
		prometheus.CounterValue,
		float64(snmp.checksumErrors))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.outCtrlChunksDesc,
		prometheus.CounterValue,
		float64(snmp.outCtrlChunks))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.outOrderChunksDesc,
		prometheus.CounterValue,
		float64(snmp.outOrderChunks))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.outUnorderChunksDesc,
		prometheus.CounterValue,
		float64(snmp.outUnorderChunks))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.inCtrlChunksDesc,
		prometheus.CounterValue,
		float64(snmp.inCtrlChunks))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.inOrderChunksDesc,
		prometheus.CounterValue,
		float64(snmp.inOrderChunks))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.inUnorderChunksDesc,
		prometheus.CounterValue,
		float64(snmp.inUnorderChunks))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.fragUsrMsgsDesc,
		prometheus.CounterValue,
		float64(snmp.fragUsrMsgs))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.reasmUsrMsgsDesc,
		prometheus.CounterValue,
		float64(snmp.reasmUsrMsgs))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.outSCTPPacksDesc,
		prometheus.CounterValue,
		float64(snmp.outSCTPPacks))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.inSCTPPacksDesc,
		prometheus.CounterValue,
		float64(snmp.inSCTPPacks))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.t1InitExpiredsDesc,
		prometheus.CounterValue,
		float64(snmp.t1InitExpireds))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.t1CookieExpiredsDesc,
		prometheus.CounterValue,
		float64(snmp.t1CookieExpireds))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.t2ShutdownExpiredsDesc,
		prometheus.CounterValue,
		float64(snmp.t2ShutdownExpireds))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.t3RtxExpiredsDesc,
		prometheus.CounterValue,
		float64(snmp.t3RtxExpireds))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.t4RtoExpiredsDesc,
		prometheus.CounterValue,
		float64(snmp.t4RtoExpireds))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.t5ShutdownGuardExpiredsDesc,
		prometheus.CounterValue,
		float64(snmp.t5ShutdownGuardExpireds))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.delaySackExpiredsDesc,
		prometheus.CounterValue,
		float64(snmp.delaySackExpireds))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.autoCloseExpiredsDesc,
		prometheus.CounterValue,
		float64(snmp.autocloseExpireds))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.t3RetransmitsDesc,
		prometheus.CounterValue,
		float64(snmp.t3Retransmits))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.pmtudRetransmitsDesc,
		prometheus.CounterValue,
		float64(snmp.pmtudRetransmits))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.fastRetransmitsDesc,
		prometheus.CounterValue,
		float64(snmp.fastRetransmits))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.inPktSoftIRQDesc,
		prometheus.CounterValue,
		float64(snmp.inPktSoftirq))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.inPktBacklogDesc,
		prometheus.CounterValue,
		float64(snmp.inPktBacklog))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.inPktDiscardsDesc,
		prometheus.CounterValue,
		float64(snmp.inPktDiscards))

	ch <- prometheus.MustNewConstMetric(
		collector.snmp.inDataChunkDiscardsDesc,
		prometheus.CounterValue,
		float64(snmp.inDataChunkDiscards))

} // Collector.Collect()

// fetchAssocs fetches /proc/net/sctp/assocs
func (collector *Collector) fetchAssocs() ([]assoc, error) {

	const assocsFile = "/proc/net/sctp/assocs"

	f, err := os.Open(assocsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w",
			assocsFile,
			err)
	}

	csvReader := csv.NewReader(bufio.NewReader(f))
	csvReader.Comma = ' '
	csvReader.TrimLeadingSpace = true

	header, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w",
			err)
	}

	csvReader.ReuseRecord = true
	var assocs []assoc

	for {

		record, err := csvReader.Read()

		if errors.Is(err, io.EOF) {
			break
		} else if err != nil && !errors.Is(err, csv.ErrFieldCount) {
			return nil, fmt.Errorf("failed to read record: %w",
				err)
		}

		if len(record) < len(header) {
			return nil, fmt.Errorf("expected num records %d to be greater than "+
				"or equal to num headers %d",
				len(record),
				len(header))
		}

		var a assoc
		var fieldIdx = -1

		for _, name := range header {
			fieldIdx++

			if fieldIdx >= len(record) {
				return nil, fmt.Errorf("unexpected index %d",
					fieldIdx)
			}

			var field = record[fieldIdx]
			var err error

			switch name {

			case "ASSOC":
				a.assoc, err = strconv.ParseUint(field, 16, 64)
			case "SOCK":
				a.sock, err = strconv.ParseUint(field, 16, 64)
			case "STY":
				a.sty, err = strconv.ParseInt(field, 10, 64)
			case "SST":
				a.sst, err = strconv.ParseInt(field, 10, 64)
			case "ST":
				a.st, err = strconv.ParseInt(field, 10, 64)
			case "HBKT":
				a.hbkt, err = strconv.ParseInt(field, 10, 64)
			case "ASSOC-ID":
				a.assocId, err = strconv.ParseInt(field, 10, 64)
			case "TX_QUEUE":
				a.txQueue, err = strconv.ParseInt(field, 10, 64)
			case "RX_QUEUE":
				a.rxQueue, err = strconv.ParseInt(field, 10, 64)
			case "UID":
				a.uid, err = strconv.ParseInt(field, 10, 64)
			case "INODE":
				a.inode, err = strconv.ParseInt(field, 10, 64)
			case "LPORT":
				a.lPort, err = strconv.ParseInt(field, 10, 64)
			case "RPORT":
				a.rPort, err = strconv.ParseInt(field, 10, 64)
			case "LADDRS":
				a.lAddrs = field
				for {
					if fieldIdx+1 >= len(record) {
						break
					}
					addr := record[fieldIdx+1]
					if addr == "<->" {
						break
					}
					if net.ParseIP(strings.TrimPrefix(addr, "*")) == nil {
						break
					}
					a.lAddrs += " " + addr
					fieldIdx++
				}
			case "RADDRS":
				a.rAddrs = field
				for {
					if fieldIdx+1 >= len(record) {
						break
					}
					addr := record[fieldIdx+1]
					if net.ParseIP(strings.TrimPrefix(addr, "*")) == nil {
						break
					}
					a.rAddrs += " " + addr
					fieldIdx++
				}
			case "HBINT":
				a.hbint, err = strconv.ParseInt(field, 10, 64)
			case "INS":
				a.ins, err = strconv.ParseInt(field, 10, 64)
			case "OUTS":
				a.outs, err = strconv.ParseInt(field, 10, 64)
			case "MAXRT":
				a.maxRT, err = strconv.ParseInt(field, 10, 64)
			case "T1X":
				a.t1x, err = strconv.ParseInt(field, 10, 64)
			case "T2X":
				a.t2x, err = strconv.ParseInt(field, 10, 64)
			case "RTXC":
				a.rtxc, err = strconv.ParseInt(field, 10, 64)
			case "wmema":
				a.wmema, err = strconv.ParseInt(field, 10, 64)
			case "wmemq":
				a.wmemq, err = strconv.ParseInt(field, 10, 64)
			case "sndbuf":
				a.sndBuf, err = strconv.ParseInt(field, 10, 64)
			case "rcvbuf":
				a.rcvBuf, err = strconv.ParseInt(field, 10, 64)

			} // switch

			if err != nil {
				return nil, fmt.Errorf("failed to read field: %w",
					err)
			}

		} // for each header

		assocs = append(assocs, a)

	} // forever

	return assocs, nil

} // Collector.fetchAssocs()

// fetchEps fetches endpoints from /proc/net/sctp/eps
func (collector *Collector) fetchEps() ([]ep, error) {

	const epsFile = "/proc/net/sctp/eps"

	f, err := os.Open(epsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w",
			epsFile,
			err)
	}

	csvReader := csv.NewReader(bufio.NewReader(f))
	csvReader.Comma = ' '
	csvReader.TrimLeadingSpace = true

	header, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w",
			err)
	}

	csvReader.ReuseRecord = true
	var eps []ep

	for {

		record, err := csvReader.Read()

		if errors.Is(err, io.EOF) {
			break
		} else if err != nil && !errors.Is(err, csv.ErrFieldCount) {
			return nil, fmt.Errorf("failed to read record: %w",
				err)
		}

		// There's a final whitespace field at the end of each record, so is
		// +1 len(header)
		if len(record) < len(header) {
			return nil, fmt.Errorf("expected num records %d to be greater than "+
				"or equal to num headers %d",
				len(record),
				len(header))
		}

		var e ep
		var fieldIdx = -1

		for _, name := range header {
			fieldIdx++

			if fieldIdx >= len(record) {
				return nil, fmt.Errorf("unexpected index %d",
					fieldIdx)
			}

			var field = record[fieldIdx]
			var err error

			switch name {
			case "ENDPT":
				e.endpt, err = strconv.ParseInt(field, 10, 64)
			case "SOCK":
				e.sock, err = strconv.ParseInt(field, 10, 64)
			case "STY":
				e.sty, err = strconv.ParseInt(field, 10, 64)
			case "SST":
				e.sst, err = strconv.ParseInt(field, 10, 64)
			case "HBKT":
				e.hbkt, err = strconv.ParseInt(field, 10, 64)
			case "LPORT":
				e.lPort, err = strconv.ParseInt(field, 10, 64)
			case "UID":
				e.uid, err = strconv.ParseInt(field, 10, 64)
			case "INODE":
				e.inode, err = strconv.ParseInt(field, 10, 64)
			case "LADDRS":
				e.lAddrs = field
				for {
					if fieldIdx+1 >= len(record) {
						break
					}
					addr := record[fieldIdx+1]
					if net.ParseIP(strings.TrimPrefix(addr, "*")) == nil {
						break
					}
					e.lAddrs += " " + addr
					fieldIdx++
				}
			} // switch

			if err != nil {
				return nil, fmt.Errorf("failed to read field: %w",
					err)
			}

		} // for each header

		eps = append(eps, e)

	} // forever

	return eps, nil

} // Collector.fetchEps()

// fetchRemAddr fetches /proc/net/sctp/redaddr
func (collector *Collector) fetchRemAddr() ([]remAddr, error) {

	const remAddrFile = "/proc/net/sctp/remaddr"

	f, err := os.Open(remAddrFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w",
			remAddrFile,
			err)
	}

	csvReader := csv.NewReader(bufio.NewReader(f))
	csvReader.Comma = ' '
	csvReader.TrimLeadingSpace = true

	header, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w",
			err)
	}

	csvReader.ReuseRecord = true
	var remAddrs []remAddr

	for {

		record, err := csvReader.Read()

		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to read record: %w",
				err)
		}

		if len(header) != len(record) {
			return nil, fmt.Errorf("expected num headers %d and num records %d "+
				"to be the same",
				len(header),
				len(record))
		}

		var r remAddr

		for i, name := range header {

			var field = record[i]
			var err error

			switch name {
			case "ADDR":
				r.addr = field
			case "ASSOC_ID":
				r.assocId, err = strconv.ParseInt(field, 10, 64)
			case "HB_ACT":
				r.hbAct, err = strconv.ParseInt(field, 10, 64)
			case "RTO":
				r.rto, err = strconv.ParseInt(field, 10, 64)
			case "MAX_PATH_RTX":
				r.maxPathRtx, err = strconv.ParseInt(field, 10, 64)
			case "REM_ADDR_RTX":
				r.remAddrRtx, err = strconv.ParseInt(field, 10, 64)
			case "START":
				r.start, err = strconv.ParseInt(field, 10, 64)
			case "STATE":
				r.state, err = strconv.ParseInt(field, 10, 64)
			}

			if err != nil {
				return nil, fmt.Errorf("failed to read field: %w",
					err)
			}

		} // for each header

		remAddrs = append(remAddrs, r)

	} // forever

	return remAddrs, nil

} // Collector.fetchRemAddr()

// fetchSnmp fetches /proc/net/sctp/snmp
func (collector *Collector) fetchSnmp() (snmp, error) {

	const snmpFile = "/proc/net/sctp/snmp"

	f, err := os.Open(snmpFile)
	if err != nil {
		return snmp{}, fmt.Errorf("failed to open file %s: %w",
			snmpFile,
			err)
	}

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanWords)

	var sn snmp

	for {

		if !scanner.Scan() {
			break
		}
		name := scanner.Text()

		if !scanner.Scan() {
			return snmp{}, fmt.Errorf("expected token")
		}

		switch name {
		case "SctpCurrEstab":
			sn.currEstab, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpActiveEstabs":
			sn.activeEstabs, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpPassiveEstabs":
			sn.passiveEstabs, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpAborteds":
			sn.aborteds, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpShutdowns":
			sn.shutdowns, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpOutOfBlues":
			sn.outOfBlues, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpChecksumErrors":
			sn.checksumErrors, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpOutCtrlChunks":
			sn.outCtrlChunks, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpOutOrderChunks":
			sn.outOrderChunks, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpOutUnorderChunks":
			sn.outUnorderChunks, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpInCtrlChunks":
			sn.inCtrlChunks, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpInOrderChunks":
			sn.inOrderChunks, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpInUnorderChunks":
			sn.inUnorderChunks, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpFragUsrMsgs":
			sn.fragUsrMsgs, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpReasmUsrMsgs":
			sn.reasmUsrMsgs, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpOutSCTPPacks":
			sn.outSCTPPacks, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpInSCTPPacks":
			sn.inSCTPPacks, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpT1InitExpireds":
			sn.t1InitExpireds, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpT1CookieExpireds":
			sn.t1CookieExpireds, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpT2ShutdownExpireds":
			sn.t2ShutdownExpireds, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpT3RtxExpireds":
			sn.t3RtxExpireds, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpT4RtoExpireds":
			sn.t4RtoExpireds, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpT5ShutdownGuardExpireds":
			sn.t5ShutdownGuardExpireds, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpDelaySackExpireds":
			sn.delaySackExpireds, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpAutocloseExpireds":
			sn.autocloseExpireds, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpT3Retransmits":
			sn.t3Retransmits, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpPmtudRetransmits":
			sn.pmtudRetransmits, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpFastRetransmits":
			sn.fastRetransmits, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpInPktSoftirq":
			sn.inPktSoftirq, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpInPktBacklog":
			sn.inPktBacklog, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpInPktDiscards":
			sn.inPktDiscards, err = strconv.ParseInt(scanner.Text(), 10, 64)
		case "SctpInDataChunkDiscards":
			sn.inDataChunkDiscards, err = strconv.ParseInt(scanner.Text(), 10, 64)
		}

		if err != nil {
			return snmp{}, fmt.Errorf("failed to parse %s: %w",
				scanner.Text(),
				err)
		}

	} // forever

	return sn, nil

} // Collector.fetchSnmp()
