package utils

import "os"

func CheckIfFileExists(path string) bool {
	_, err := os.Open(path)
	return err == nil
}
