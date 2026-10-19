# New owned-VM dependency image only; the old executor is retained unchanged.
# The nested Guard sandbox already binds /usr readonly. Keep runtime dependencies
# inside that closure rather than adding mounts, capabilities or task permissions.
FROM fb372d771d49494e81b7f853d51ce7a6ae208013015a1b237f0becdbdc301dda
COPY install_usr_node_runtime.py /usr/share/hol-benchmark/install_usr_node_runtime.py
RUN ["/usr/bin/python3", "-I", "-B", "/usr/share/hol-benchmark/install_usr_node_runtime.py"]
USER 65532:65532
