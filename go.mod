module github.com/josedonizetti/tracee-grpc-client

go 1.21

toolchain go1.21.6

require (
	github.com/aquasecurity/tracee/api v0.0.0-20231006160439-f3bc7d1e9299
	github.com/aquasecurity/tracee/types v0.0.0-20231006160439-f3bc7d1e9299
	google.golang.org/grpc v1.58.3
	google.golang.org/protobuf v1.33.0
)

replace github.com/aquasecurity/tracee/api => github.com/rscampos/tracee/api 1098_global_event_id_num

require (
	github.com/golang/protobuf v1.5.3 // indirect
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto v0.0.0-20231002182017-d307bd883b97 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230920204549-e6e6cdab5c13 // indirect
)
