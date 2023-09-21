package main

import (
	"log"
	"sync"
	"time"

	"github.com/tester2024/telnet"
	"github.com/tester2024/telnet/linereader"
	"github.com/tester2024/telnet/options"
)

func main() {
	svr := telnet.NewServer(":9999", telnet.HandleFunc(exampleHandler), options.NAWSOption)
	svr.ListenAndServe()
}

func exampleHandler(c *telnet.Connection) {
	log.Printf("Connection received: %s", c.RemoteAddr())
	lr := linereader.New()
	go lr.ReadLines(c)

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for line := range lr.C {
			log.Printf("Received line: %v", line)
		}
	}()
	time.Sleep(time.Millisecond)
	nh := c.OptionHandlers[telnet.TeloptNAWS].(*options.NAWSHandler)
	log.Printf("Client width: %d, height: %d", nh.Width, nh.Height)
	wg.Wait()
	log.Printf("Goodbye %s!", c.RemoteAddr())
}
