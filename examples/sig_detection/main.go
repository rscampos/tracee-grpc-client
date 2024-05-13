package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func main() {
	kk := keepalive.ClientParameters{
		Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
		Timeout:             time.Second,      // wait 1 second for ping ack before considering the connection dead
		PermitWithoutStream: true,             // send pings even without active streams
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	opts = append(opts, grpc.WithKeepaliveParams(kk))

	conn, err := grpc.Dial(":4466", opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewTraceeServiceClient(conn)

	stream, err := client.StreamEvents(context.Background(), &pb.StreamEventsRequest{
		Mask: &fieldmaskpb.FieldMask{
			Paths: []string{
				"name",
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		idEvent := event.Event.Id
		fmt.Println("receive event:", int(idEvent))
		switch(idEvent){
			case pb.Id_read:
				fmt.Println("This is read:", pb.Id_read, " id:", int(idEvent))
			case pb.Id_execve:
				fmt.Println("This is execve:", pb.Id_execve, " id:", int(idEvent))
			case pb.Id_security_socket_connect:
				fmt.Println("This is security_socket_connect:", pb.Id_security_socket_connect, " id:", int(idEvent))
			case pb.Id_unspecified:
				fmt.Println("This is Id_unspecified. Id:", int(idEvent))
			default:
				fmt.Println("This is default")
		}
	}
}
