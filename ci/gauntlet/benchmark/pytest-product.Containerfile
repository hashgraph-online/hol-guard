# Owned-VM mechanical containment control, separate from existing executor images.
# The build context must supply exact uv.lock wheel bytes verified before unpacking.
FROM sha256:830e10601acaaa774387277dec0f6c6f9b1c8f20ef970edab27bcf9028d5ca66
COPY python/ /usr/local/lib/python3.12/dist-packages/
USER 65532:65532
