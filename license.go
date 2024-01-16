package licenselib

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
)

func Init() {
	defer licenseError()
	if !isFileExists("activation.cl") {
		createActivation()
	}
}

func createActivation() {
	panic(fmt.Errorf("please get the"))
}

func isFileExists(posisi string) bool {
	_, err := os.Stat(posisi)
	return err != nil
}

func licenseError() {
	if r := recover(); r != nil {
		log.Println("Catched", r)
		log.Println("Stack", string(debug.Stack()))
		os.Exit(0)
	}
}
