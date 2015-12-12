# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(student-test-2) begin
(student-test-2) create "temp_test.txt"
(student-test-2) open "temp_test.txt"
(student-test-2) not the expected order of writes
(student-test-2) end
EOF
pass;