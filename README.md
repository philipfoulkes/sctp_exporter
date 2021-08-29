# sctp_exporter
Stream Control Transmission Protocol (SCTP) Prometheus Exporter for Linux. It
fetches metrics from /proc/net/sctp/* and exposes them in Prometheus format.

All the metrics under /proc/net/sctp/* have been mapped and are being exposed
in Prometheus format, thus this exporter should be complete. Bugs and errors
may still be found as it gets deploy it into production, thus changes to this
exporter can be expected.