# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(student-test-1) begin
(student-test-1) number of hits is not greater the second time
(student-test-1) end
EOF
pass;