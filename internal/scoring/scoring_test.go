package scoring

import "testing"

func TestLetter(t *testing.T) {
	cases := map[int]string{100: "A", 90: "A", 89: "B", 75: "B", 74: "C", 60: "C", 59: "D", 40: "D", 39: "F", 0: "F"}
	for score, want := range cases {
		if got := Letter(score); got != want {
			t.Errorf("Letter(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestColor(t *testing.T) {
	if Color(95) != Color(80) {
		t.Error("A and B should share a color")
	}
	if Color(65) == Color(95) {
		t.Error("C should differ from A")
	}
	if Color(10) != "#f85149" {
		t.Errorf("F color = %s", Color(10))
	}
}
