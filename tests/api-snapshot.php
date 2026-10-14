<?php

/*
 * Prints the API snapshot of src/Iodev/Whois as JSON.
 * It was used once on the untouched 4.1.10 sources to create
 * tests/Iodev/Whois/Compat/api-4.1.10.json:
 *
 *   php tests/api-snapshot.php > tests/Iodev/Whois/Compat/api-4.1.10.json
 */

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require __DIR__ . '/Iodev/Whois/Compat/ApiSnapshot.php';

echo json_encode(
    \Iodev\Whois\Compat\ApiSnapshot::build(__DIR__ . '/../src/Iodev/Whois'),
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
), "\n";
