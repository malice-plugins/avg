package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fatih/structs"
	"github.com/gorilla/mux"
	"github.com/maliceio/go-plugin-utils/database/elasticsearch"
	"github.com/maliceio/go-plugin-utils/utils"
	"github.com/maliceio/malice/utils/clitable"
	"github.com/parnurzeal/gorequest"
	"github.com/urfave/cli"
)

// Version stores the plugin's version
var Version string

// BuildTime stores the plugin's build time
var BuildTime string

const (
	name     = "avg"
	category = "av"
)

type pluginResults struct {
	ID   string      `json:"id" structs:"id,omitempty"`
	Data ResultsData `json:"avast" structs:"avg"`
}

// AVG json object
type AVG struct {
	Results ResultsData `json:"avg"`
}

// ResultsData json object
type ResultsData struct {
	Infected bool   `json:"infected" structs:"infected"`
	Result   string `json:"result" structs:"result"`
	Engine   string `json:"engine" structs:"engine"`
	Database string `json:"database" structs:"database"`
	Updated  string `json:"updated" structs:"updated"`
}

// AvScan performs antivirus scan
func AvScan(path string, timeout int) AVG {

	// Give avgd 10 seconds to finish
	avgdCtx, avgdCancel := context.WithTimeout(context.Background(), time.Duration(10)*time.Second)
	defer avgdCancel()
	// AVG needs to have the daemon started first
	_, err := utils.RunCommand(avgdCtx, "/etc/init.d/avgd", "start")
	utils.Assert(err)

	var results ResultsData

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	output, err := utils.RunCommand(ctx, "/usr/bin/avgscan", path)
	results, err = ParseAVGOutput(output, err, path)

	if err != nil {
		// If fails try a second time
		output, err := utils.RunCommand(ctx, "/usr/bin/avgscan", path)
		results, err = ParseAVGOutput(output, err, path)
		utils.Assert(err)
	}

	return AVG{
		Results: results,
	}
}

// ParseAVGOutput convert avg output into ResultsData struct
func ParseAVGOutput(avgout string, err error, path string) (ResultsData, error) {

	if err != nil {
		return ResultsData{}, err
	}

	log.Debug("AVG Output: ", avgout)

	avg := ResultsData{
		Infected: false,
		Engine:   getAvgVersion(),
	}
	colonSeparated := []string{}

	lines := strings.Split(avgout, "\n")
	// Extract Virus string and extract colon separated lines into an slice
	for _, line := range lines {
		if len(line) != 0 {
			if strings.Contains(line, ":") {
				colonSeparated = append(colonSeparated, line)
			}
			if strings.Contains(line, path) {
				pathVirusString := strings.Split(line, "  ")
				avg.Result = strings.TrimSpace(pathVirusString[1])
			}
		}
	}
	// fmt.Println(lines)

	// Extract AVG Details from scan output
	if len(colonSeparated) != 0 {
		for _, line := range colonSeparated {
			if len(line) != 0 {
				keyvalue := strings.Split(line, ":")
				if len(keyvalue) != 0 {
					switch {
					case strings.Contains(line, "Virus database version"):
						avg.Database = strings.TrimSpace(keyvalue[1])
					case strings.Contains(line, "Virus database release date"):
						date := strings.TrimSpace(strings.TrimPrefix(line, "Virus database release date:"))
						avg.Updated = parseUpdatedDate(date)
					case strings.Contains(line, "Infections found"):
						if strings.Contains(keyvalue[1], "1") {
							avg.Infected = true
						}
					}
				}
			}
		}
	} else {
		log.Error("[ERROR] colonSeparated was empty: ", colonSeparated)
		log.Errorf("[ERROR] AVG output was: \n%s", avgout)
		// fmt.Println("[ERROR] colonSeparated was empty: ", colonSeparated)
		// fmt.Printf("[ERROR] AVG output was: \n%s", avgout)
		return ResultsData{}, errors.New("Unable to parse AVG output")
	}

	return avg, nil
}

// Get Anti-Virus scanner version
func getAvgVersion() string {
	versionOut, err := utils.RunCommand(nil, "/usr/bin/avgscan", "-v")
	utils.Assert(err)

	log.Debug("AVG Version: ", versionOut)

	lines := strings.Split(versionOut, "\n")
	for _, line := range lines {
		if len(line) != 0 {
			keyvalue := strings.Split(line, ":")
			if len(keyvalue) != 0 {
				if strings.Contains(keyvalue[0], "Anti-Virus scanner version") {
					return strings.TrimSpace(keyvalue[1])
				}
			}
		}
	}
	return ""
}

func parseUpdatedDate(date string) string {
	layout := "Mon, 02 Jan 2006 15:04:05 +0000"
	t, _ := time.Parse(layout, date)
	return fmt.Sprintf("%d%02d%02d", t.Year(), t.Month(), t.Day())
}

func getUpdatedDate() string {
	if _, err := os.Stat("/opt/malice/UPDATED"); os.IsNotExist(err) {
		return BuildTime
	}
	updated, err := ioutil.ReadFile("/opt/malice/UPDATED")
	utils.Assert(err)
	return string(updated)
}

func updateAV(ctx context.Context) error {
	fmt.Println("Updating AVG...")
	// AVG needs to have the daemon started first
	exec.Command("/etc/init.d/avgd", "start").Output()

	fmt.Println(utils.RunCommand(nil, "avgupdate"))
	// Update UPDATED file
	t := time.Now().Format("20060102")
	err := ioutil.WriteFile("/opt/malice/UPDATED", []byte(t), 0644)
	return err
}

func printMarkDownTable(avg AVG) {

	fmt.Println("#### AVG")
	table := clitable.New([]string{"Infected", "Result", "Engine", "Updated"})
	table.AddRow(map[string]interface{}{
		"Infected": avg.Results.Infected,
		"Result":   avg.Results.Result,
		"Engine":   avg.Results.Engine,
		"Updated":  avg.Results.Updated,
	})
	table.Markdown = true
	table.Print()
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(body)
}

func webService() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/scan", webAvScan).Methods("POST")
	log.Info("web service listening on port :3993")
	log.Fatal(http.ListenAndServe(":3993", router))
}

func webAvScan(w http.ResponseWriter, r *http.Request) {

	r.ParseMultipartForm(32 << 20)
	file, header, err := r.FormFile("malware")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Please supply a valid file to scan.")
		log.Error(err)
	}
	defer file.Close()

	log.Debug("Uploaded fileName: ", header.Filename)

	tmpfile, err := ioutil.TempFile("/malware", "web_")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	data, err := ioutil.ReadAll(file)

	if _, err = tmpfile.Write(data); err != nil {
		log.Fatal(err)
	}
	if err = tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	// Do AV scan
	avg := AvScan(tmpfile.Name(), 60)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(avg); err != nil {
		log.Fatal(err)
	}
}

func main() {

	var elastic string

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "avg"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice AVG AntiVirus Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "elasitcsearch",
			Value:       "",
			Usage:       "elasitcsearch address for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH",
			Destination: &elastic,
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.BoolFlag{
			Name:   "callback, c",
			Usage:  "POST results back to Malice webhook",
			EnvVar: "MALICE_ENDPOINT",
		},
		cli.BoolFlag{
			Name:   "proxy, x",
			Usage:  "proxy settings for Malice webhook endpoint",
			EnvVar: "MALICE_PROXY",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  60,
			Usage:  "malice plugin timeout (in seconds)",
			EnvVar: "MALICE_TIMEOUT",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:  "update",
			Usage: "Update virus definitions",
			Action: func(c *cli.Context) error {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Int("timeout"))*time.Second)
				defer cancel()

				return updateAV(ctx)
			},
		},
		{
			Name:  "web",
			Usage: "Create a AVG scan web service",
			Action: func(c *cli.Context) error {
				// ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Int("timeout"))*time.Second)
				// defer cancel()

				webService()

				return nil
			},
		},
	}
	app.Action = func(c *cli.Context) error {

		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {
			path, err := filepath.Abs(c.Args().First())
			utils.Assert(err)

			if _, err := os.Stat(path); os.IsNotExist(err) {
				utils.Assert(err)
			}

			avg := AvScan(path, c.Int("timeout"))

			// upsert into Database
			elasticsearch.InitElasticSearch(elastic)
			elasticsearch.WritePluginResultsToDatabase(elasticsearch.PluginResults{
				ID:       utils.Getopt("MALICE_SCANID", utils.GetSHA256(path)),
				Name:     name,
				Category: category,
				Data:     structs.Map(avg.Results),
			})

			if c.Bool("table") {
				printMarkDownTable(avg)
			} else {
				avgJSON, err := json.Marshal(avg)
				utils.Assert(err)
				if c.Bool("callback") {
					request := gorequest.New()
					if c.Bool("proxy") {
						request = gorequest.New().Proxy(os.Getenv("MALICE_PROXY"))
					}
					request.Post(os.Getenv("MALICE_ENDPOINT")).
						Set("X-Malice-ID", utils.Getopt("MALICE_SCANID", utils.GetSHA256(path))).
						Send(string(avgJSON)).
						End(printStatus)

					return nil
				}
				fmt.Println(string(avgJSON))
			}
		} else {
			log.Fatal(fmt.Errorf("Please supply a file to scan with malice/avg"))
		}
		return nil
	}

	err := app.Run(os.Args)
	utils.Assert(err)
}
