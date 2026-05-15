#pragma once

// Install the Tendermint privval TCP listener on port 26658.
// Call once after eth_init() when in PrivVal mode.
//
// Step 3b: stub handler -- accepts connections, recognizes nothing, echoes
//          a fixed framed reply. Real protobuf parsing + signing is Step 4+.
void privval_init(void);
