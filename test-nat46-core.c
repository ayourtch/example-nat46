#include <stdio.h>
#include <stdlib.h>
#include "debug-ay.h"
#include "nat46-glue.h"

struct debug_type DBG_TEST_S = { "test", "TEST", 0, 0 };
debug_type_t DBG_TEST = &DBG_TEST_S;





int test_config(nat46_instance_t *nat46, char *cfg_str) {
  char *buf = malloc(strlen(cfg_str) + 1);
  memcpy(buf, cfg_str, strlen(cfg_str) + 1);

  debug(DBG_TEST, 0, "Configuring the nat46 instance from string: %s", buf);
  nat46_set_config(nat46, buf, strlen(buf));
  debug_dump(DBG_TEST, 0, nat46, sizeof(*nat46));
  return 0;
}

int main(int argc, char *argv[]) {
  nat46_instance_t *nat46;

  debug_show_timestamp(0);

  nat46 = get_nat46_instance(NULL);
  test_config(nat46, "debug 1 v6bits 2001:db8::1");
  test_config(nat46, "debug 2\nv6bits 2001:db8::2");
  test_config(nat46, "v6bits 2001:db8::3 debug 3\n");
  test_config(nat46, "nat64pref 64:ff9b::/96 \n v6bits 2001:db8::4\n \ndebug 4\n");
  test_config(nat46, "v4addr 100.64.1.3");

  return 0;
}
