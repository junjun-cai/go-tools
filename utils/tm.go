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
// * 	-week start with monday and end with sunday.
// * HISTORY:
// *    -create: 2021/12/14 10:57:12 ColeCai.
// * 	-update: 2021/12/31 14:39:14 ColeCai.fix bug when weekday is sunday.
// ***********************************************************************************************
func CurWeekLeftSecond() int64 {
	return CurWeekEnd() - time.Now().Unix()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-week start with monday and end with sunday.
// * HISTORY:
// *    -create: 2022/12/31 14:22:33 ColeCai.
// ***********************************************************************************************
func CurWeekStart() int64 {
	return WeekStart(time.Now()).Unix()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-week start with monday and end with sunday.
// * 	-current day 24 o'clock is same as after day 0 o'clock. but 24 o'clock timestamp transform
//		 standard time is after day's date.so here use 23:59:59 as day end time.if you want accurate
//		 timestamp please add 1 second.
// * HISTORY:
// *    -create: 2022/12/31 14:24:28 ColeCai.
// ***********************************************************************************************
func CurWeekEnd() int64 {
	return WeekEnd(time.Now()).Unix()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/31 14:41:28 ColeCai.
// ***********************************************************************************************
func GetMonthDays(year, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	default:
		if IsLeapYear(year) {
			return 29
		}
		return 28
	}
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/31 14:58:53 ColeCai.
// ***********************************************************************************************
func IsLeapYear(year int) bool {
	return year%400 == 0 || (year%4 == 0 && year%100 != 0)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/31 14:59:41 ColeCai.
// ***********************************************************************************************
func CurMonthStart() int64 {
	return MonthStart(time.Now()).Unix()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/31 15:09:46 ColeCai.
// ***********************************************************************************************
func CurMonthEnd() int64 {
	return MonthEnd(time.Now()).Unix()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/31 15:19:43 ColeCai.
// ***********************************************************************************************
func CurMonthLeftSecond() int64 {
	return CurMonthEnd() - time.Now().Unix()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/31 15:20:23 ColeCai.
// ***********************************************************************************************
func MonthStart(t time.Time) time.Time {
	days := t.Day()
	stm := t.AddDate(0, 0, -days+1)
	return time.Date(stm.Year(), stm.Month(), stm.Day(), 0, 0, 0, 0, stm.Location())
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-current day 24 o'clock is same as after day 0 o'clock. but 24 o'clock timestamp transform
//		 standard time is after day's date.so here use 23:59:59 as day end time.if you want accurate
//		 timestamp please add 1 second.
// * HISTORY:
// *    -create: 2022/12/31 15:20:57 ColeCai.
// ***********************************************************************************************
func MonthEnd(t time.Time) time.Time {
	year := t.Year()
	month := t.Month()
	monthDays := GetMonthDays(year, int(month))
	etm := t.AddDate(0, 0, monthDays-t.Day())
	return time.Date(etm.Year(), etm.Month(), etm.Day(), 23, 59, 59, 0, etm.Location())
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/31 15:22:06 ColeCai.
// ***********************************************************************************************
func WeekStart(t time.Time) time.Time {
	weekDay := t.Weekday()
	if weekDay == time.Sunday {
		weekDay = 7
	}
	ntm := t.AddDate(0, 0, -int(weekDay)+1)
	return time.Date(ntm.Year(), ntm.Month(), ntm.Day(), 0, 0, 0, 0, ntm.Location())
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-current day 24 o'clock is same as after day 0 o'clock. but 24 o'clock timestamp transform
//		 standard time is after day's date.so here use 23:59:59 as day end time.if you want accurate
//		 timestamp please add 1 second.
// * HISTORY:
// *    -create: 2022/12/31 15:23:15 ColeCai.
// ***********************************************************************************************
func WeekEnd(t time.Time) time.Time {
	weekDay := t.Weekday()
	if weekDay == time.Sunday {
		weekDay = 7
	}
	ntm := t.AddDate(0, 0, 7-int(weekDay))
	return time.Date(ntm.Year(), ntm.Month(), ntm.Day(), 23, 59, 59, 0, ntm.Location())
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-yesterday n o'clock to today n o'clock format to yesterday date. today n o'clock to
// * 	 tomorrow n o'clock format to today date.
// * 	 eg: 2022-01-01 06:00:00 - 2022-01-02 06:00:00 is 2022-01-01
// * HISTORY:
// *    -create: 2022/01/06 15:33:56 ColeCai.
// ***********************************************************************************************
func DateByClock(n int, tm time.Time) time.Time {
	hour := tm.Hour()
	if hour < n {
		return tm.AddDate(0, 0, -1)
	} else {
		return tm
	}
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * 	-yesterday n o'clock to today n o'clock format to yesterday date. today n o'clock to
// * 	 tomorrow n o'clock format to today date.
// * 	 eg: 2022-01-01 06:00:00 - 2022-01-02 06:00:00 is 2022-01-01
// * HISTORY:
// *    -create: 2022/01/06 15:38:57 ColeCai.
// ***********************************************************************************************
func DateStrByClock(n int, layout string) string {
	tm := DateByClock(n, time.Now())
	return tm.Format(layout)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/02/14 11:19:45 ColeCai.
// ***********************************************************************************************
func GetTimeWeek(tm time.Time) int {
	_, week := tm.ISOWeek()
	return week
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/02/14 11:21:11 ColeCai.
// ***********************************************************************************************
func GetCutWeek() int {
	return GetTimeWeek(time.Now())
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/02/14 11:21:41 ColeCai.
// ***********************************************************************************************
func GetTimeYearWeek(tm time.Time) (int, int) {
	return tm.ISOWeek()
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/02/14 11:22:14 ColeCai.
// ***********************************************************************************************
func GetCurYearWeek() (int, int) {
	return GetTimeYearWeek(time.Now())
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/02/14 11:22:58 ColeCai.
// ***********************************************************************************************
func GetTimeStampWeek(tm int64) int {
	t := time.Unix(tm, 0)
	return GetTimeWeek(t)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/02/14 11:24:02 ColeCai.
// ***********************************************************************************************
func GetTimeStampYearWeek(tm int64) (int, int) {
	t := time.Unix(tm, 0)
	return GetTimeYearWeek(t)
}
