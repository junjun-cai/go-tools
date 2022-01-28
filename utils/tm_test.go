//*********************************************************************************
//@Auth:蔡君君
//@Date:2021/12/31 14:26
//@File:tm_test.go
//@Pack:utils
//@Proj:go-tools
//@Ides:GoLand
//@Desc:
//*********************************************************************************

package utils

import (
	"fmt"
	"testing"
	"time"
)

type Weekday int

const (
	Sunday Weekday = iota
	Monday
	Tuesday
	Wednesday
	Thursday
	Friday
	Saturday
)

type Month int

const (
	January Month = 1 + iota
	February
	March
	April
	May
	June
	July
	August
	September
	October
	November
	December
)

func TestTm(t *testing.T) {
	fmt.Println("Sunday:", Sunday)
	fmt.Println("Monday:", Monday)
	fmt.Println("Tuesday:", Tuesday)
	fmt.Println("Wednesday:", Wednesday)
	fmt.Println("Thursday:", Thursday)
	fmt.Println("Friday:", Friday)
	fmt.Println("Saturday:", Saturday)

	fmt.Println("January:", January)
	fmt.Println("December:", December)
	tm := time.Now()
	fmt.Println("Y:", tm.Year())
	fmt.Println("m:", tm.Month())
	fmt.Println("d:", tm.Day())
}

func TestTtm(t *testing.T) {
	mst := CurMonthStart()
	fmt.Println("MS:", mst)
	wst := CurWeekStart()
	fmt.Println("WS:", wst)
	wet := CurWeekEnd()
	fmt.Println("WE:", wet)
	f := time.Unix(wet, 0)
	fmt.Println("SSS:", f.Year(), f.Month(), f.Day())
}
