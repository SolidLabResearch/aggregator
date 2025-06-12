package auth

func contains(arr []string, target string) bool {
	for _, val := range arr {
		if val == target {
			return true
		}
	}
	return false
}
