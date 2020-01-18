// Use of this source code is governed by the license that can be found in LICENSE file.

package math

import "math"

// MinInt returns the min number as an int.
func MinInt(a, b int) int {
	return int(math.Min(float64(a), float64(b)))
}

// MaxInt returns the max number as an int.
func MaxInt(a, b int) int {
	return int(math.Max(float64(a), float64(b)))
}

// AbsInt returns the abs number as an int.
func AbsInt(a int) int {
	return int(math.Abs(float64(a)))
}
