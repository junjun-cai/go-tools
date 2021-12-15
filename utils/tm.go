// ***********************************************************************************************
// ***                               G O L A N D   S T U D I O S                               ***
// ***********************************************************************************************
// * Auth: ColeCai
// * Date: 2021/12/14 10:48:14
// * File: utils.go
// * Proj: go-tools
// * Pack: utils
// * Ides: GoLand
// *----------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package utils

import "time"

const (
	MinuteSecond = 60
	HourSecond   = MinuteSecond * 60
	DaySecond    = HourSecond * 24
)

// ***********************************************************************************************
// * SUMMARY:
// * WARNING: input params is timestamp.
// * HISTORY:
// *    -create: 2021/12/14 10:50:40 ColeCai.
// ***********************************************************************************************
func IsSameDay(time1, time2 int64) bool {
	tm1 := time.Unix(time1, 0)
	tm2 := time.Unix(time2, 0)
	return tm1.Year() == tm2.Year() && tm1.YearDay() == tm2.YearDay()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING: input param is timestamp.
// * HISTORY:
// *    -create: 2021/12/14 10:51:33 ColeCai.
// ***********************************************************************************************
func IsCurDay(tm int64) bool {
	tm1 := time.Now()
	tm2 := time.Unix(tm, 0)
	return tm1.Year() == tm2.Year() && tm1.YearDay() == tm2.YearDay()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING: input params is timestamp.
// * HISTORY:
// *    -create: 2021/12/14 10:52:02 ColeCai.
// ***********************************************************************************************
func IsSameWeek(time1, time2 int64) bool {
	tm1 := time.Unix(time1, 0)
	tm2 := time.Unix(time2, 0)
	if tm1.Year() != tm2.Year() {
		return false
	}
	_, week1 := tm1.ISOWeek()
	_, week2 := tm2.ISOWeek()
	return week1 == week2
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING: input param is timestamp.
// * HISTORY:
// *     -create: 2021/12/14 10:53:21 ColeCai.
// ***********************************************************************************************
func IsCurWeek(tm int64) bool {
	tm1 := time.Now()
	tm2 := time.Unix(tm, 0)
	if tm1.Year() != tm2.Year() {
		return false
	}
	_, week1 := tm1.ISOWeek()
	_, week2 := tm2.ISOWeek()
	return week1 == week2
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING: input params is timestamp.
// * HISTORY:
// *    -create: 2021/12/14 10:54:32 ColeCai.
// ***********************************************************************************************
func IsSameMonth(time1, time2 int64) bool {
	tm1 := time.Unix(time1, 0)
	tm2 := time.Unix(time2, 0)
	return tm1.Year() == tm2.Year() && tm1.Month() == tm2.Month()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING: input param is timestamp.
// * HISTORY:
// *    -create: 2021/12/14 10:55:18 ColeCai.
// ***********************************************************************************************
func IsCurMonth(tm int64) bool {
	tm1 := time.Now()
	tm2 := time.Unix(tm, 0)
	return tm1.Year() == tm2.Year() && tm1.Month() == tm2.Month()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/14 10:56:32 ColeCai.
// ***********************************************************************************************
func CurDayLeftSecond() int64 {
	curTm := time.Now()
	endTm := time.Date(curTm.Year(), curTm.Month(), curTm.Day(), 24, 0, 0, 0, curTm.Location()).Unix()
	return endTm - curTm.Unix()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2021/12/14 10:57:12 ColeCai.
// ***********************************************************************************************
func CurWeekLeftSecond() int64 {
	now := time.Now()
	weekDay := now.Weekday()
	ntm := now.AddDate(0, 0, 7-int(weekDay)+1)
	ttm := time.Date(ntm.Year(), ntm.Month(), ntm.Day(), 0, 0, 0, 0, ntm.Location())
	return ttm.Unix() - now.Unix()
}
