/*
 * Copyright 2022 Libre Technologies Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package zero

import (
	"context"
	"crypto/tls"
	"github.com/dgraph-io/ristretto/z"
	MQTT "github.com/eclipse/paho.mqtt.golang"
	"github.com/go-co-op/gocron"
	"github.com/golang/glog"
	"strconv"
	"time"
)

const (
	tick = 1 * time.Minute
)
const (
	tickerDefaults = "cron='0 * * * *'; server='tcp://127.0.0.1:1883';topic='Libre/events/tick/everyHour'; user=admin; password=public "
)

// Publish 1 minute ticks to MQTT
func (s *Server) CronScheduler(ctx context.Context) {
	ticker := z.NewSuperFlag(Zero.Conf.GetString("ticker")).MergeAndCheckDefault(
		tickerDefaults)
	glog.Info("CronScheduler Called")
	glog.Info(ticker.GetString("cron"))
	glog.Info(ticker.GetString("server"))
	glog.Info(ticker.GetString("topic"))
	glog.Info(ticker.GetString("user"))
	glog.Info(ticker.GetString("password"))
	scheduler := gocron.NewScheduler(time.UTC)
	scheduler.Cron(ticker.GetString("cron")).Do(s.publishTimeToMQTT)
	scheduler.StartBlocking()

}
func (s *Server) publishTimeToMQTT() {
	if !s.Node.AmLeader() {
		glog.Info("CronJobExecuted, but zero is not leader")
		return
	}

	ticker := z.NewSuperFlag(Zero.Conf.GetString("ticker")).MergeAndCheckDefault(
		tickerDefaults)
	glog.Info(ticker.GetString("cron"))
	glog.Info(ticker.GetString("server"))
	glog.Info(ticker.GetString("topic"))
	glog.Info(ticker.GetString("user"))
	glog.Info(ticker.GetString("password"))
	server := ticker.GetString("server")
	topic := ticker.GetString("topic")
	qos := 1
	retained := false
	clientid := strconv.Itoa(time.Now().Second())
	username := ticker.GetString("user")
	password := ticker.GetString("password")

	connOpts := MQTT.NewClientOptions().AddBroker(server).SetClientID(clientid).SetCleanSession(true)
	if username != "" {
		connOpts.SetUsername(username)
		if password != "" {
			connOpts.SetPassword(password)
		}
	}
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ClientAuth: tls.NoClientCert}
	connOpts.SetTLSConfig(tlsConfig)

	client := MQTT.NewClient(connOpts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		glog.Error(token.Error())
		return
	}
	glog.Infof("Connected to %s\n", server)

	if token := client.Publish(topic, byte(qos), retained, time.Now().UTC().String()); token.Wait() && token.Error() != nil {
		glog.Error(token.Error())
		return
	}
}
