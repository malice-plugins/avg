package main

const tpl = `#### AVG
{{- with .Results }}
| Infected      | Result      | Engine      | Updated      |
|:-------------:|:-----------:|:-----------:|:------------:|
| {{.Infected}} | {{.Result}} | {{.Engine}} | {{.Updated}} |
{{ end -}}
`

// func printMarkDownTable(avg AVG) {
//
// 	fmt.Println("#### AVG")
// 	table := clitable.New([]string{"Infected", "Result", "Engine", "Updated"})
// 	table.AddRow(map[string]interface{}{
// 		"Infected": avg.Results.Infected,
// 		"Result":   avg.Results.Result,
// 		"Engine":   avg.Results.Engine,
// 		"Updated":  avg.Results.Updated,
// 	})
// 	table.Markdown = true
// 	table.Print()
// }
