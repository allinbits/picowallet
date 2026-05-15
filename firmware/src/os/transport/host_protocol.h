#pragma once

// Parse one line from the host, dispatch to OS or to an app, send "ok ..."
// or "err ..." back, and refresh the on-device console. May mutate `line`.
void host_protocol_dispatch(char *line);
