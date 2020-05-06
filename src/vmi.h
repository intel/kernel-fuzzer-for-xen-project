#ifndef VMI_H
#define VMI_H

bool setup_vmi(vmi_instance_t *vmi, char *domain, uint64_t domid, char *json, bool init_events, bool init_os);
void loop(vmi_instance_t vmi);
void free_event(vmi_event_t *event, status_t status);

#endif
