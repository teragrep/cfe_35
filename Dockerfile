FROM rockylinux:8
COPY rpm/target/rpm/com.teragrep-cfe_35/RPMS/noarch/com.teragrep-cfe_35-*.rpm /cfe_35.rpm
RUN dnf install -y /cfe_35.rpm && rm -f /cfe_35.rpm && dnf clean all
USER srv-cfe_35
ENTRYPOINT ["/usr/bin/java"]
CMD ["-jar", "/opt/teragrep/cfe_35/lib/cfe_35.jar"]
