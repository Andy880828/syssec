package intel

import (
	"fmt"
	"math"
	"strings"
)

// CVSS3Base computes the CVSS v3.0/v3.1 base score from a vector string
// such as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
func CVSS3Base(vector string) (float64, error) {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, fmt.Errorf("not a CVSS v3 vector: %q", vector)
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	val := map[string]float64{}
	for k, table := range weights {
		w, ok := table[m[k]]
		if !ok {
			return 0, fmt.Errorf("CVSS vector missing/invalid %s", k)
		}
		val[k] = w
	}
	changed := m["S"] == "C"
	if m["S"] != "U" && !changed {
		return 0, fmt.Errorf("CVSS vector missing/invalid S")
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	prv, ok := pr[m["PR"]]
	if !ok {
		return 0, fmt.Errorf("CVSS vector missing/invalid PR")
	}
	iss := 1 - (1-val["C"])*(1-val["I"])*(1-val["A"])
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, nil
	}
	exploit := 8.22 * val["AV"] * val["AC"] * prv * val["UI"]
	if changed {
		return roundUp(math.Min(1.08*(impact+exploit), 10)), nil
	}
	return roundUp(math.Min(impact+exploit, 10)), nil
}

// roundUp implements the CVSS v3.1 Roundup function.
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
