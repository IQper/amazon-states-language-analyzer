package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)
func main() {
	jsonFile, err := os.Open("Events.json")
	if err != nil {
		fmt.Println(err)
	}

	jsonData, _ := ioutil.ReadAll(jsonFile)
	var result map[string]interface{}
	_ = json.Unmarshal(jsonData, &result)
	_ = jsonFile.Close()

	statesRaw := result["States"].(map[string]interface{})
	var states map[string]State

	for name := range statesRaw {
		currentState := statesRaw[name].(map[string]interface{})

		var end = false
		if currentState["End"] != nil {
			end = true
		}
		var next = ""
		if currentState["Next"] != nil{
			next = fmt.Sprint(currentState["Next"])
		}
		var resource = fmt.Sprint(currentState["Resource"])

		var data = Data{end, next, resource}
		states[name] = State{name, data}
	}
	fmt.Printf("Keys: %v\n", states)
}

type State struct {
	Name string
	Data Data
}

type Data struct{
	End bool
	Next string
	Resource string
}