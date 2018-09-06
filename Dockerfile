####################################################
# GOLANG BUILDER
####################################################
FROM golang:1.11 as go_builder

COPY . /go/src/github.com/malice-plugins/avg
WORKDIR /go/src/github.com/malice-plugins/avg
RUN go get -u github.com/golang/dep/cmd/dep && dep ensure
RUN go build -ldflags "-s -w -X main.Version=v$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/avscan

####################################################
# PLUGIN BUILDER
####################################################
FROM debian:jessie

LABEL maintainer "https://github.com/blacktop"

LABEL malice.plugin.repository = "https://github.com/malice-plugins/avg.git"
LABEL malice.plugin.category="av"
LABEL malice.plugin.mime="*"
LABEL malice.plugin.docker.engine="*"

# Create a malice user and group first so the IDs get set the same way, even as
# the rest of this may change over time.
RUN groupadd -r malice \
  && useradd --no-log-init -r -g malice malice \
  && mkdir /malware \
  && chown -R malice:malice /malware

# Install Requirements
RUN buildDeps='ca-certificates curl' \
  && apt-get update -qq \
  && apt-get install -yq $buildDeps libc6-i386 lib32z1 --no-install-recommends \
  && echo "===> Install AVG..." \
  && curl -Ls http://download.avgfree.com/filedir/inst/avg2013flx-r3118-a6926.i386.deb > /tmp/avg.deb \
  && dpkg -i /tmp/avg.deb \
  && /etc/init.d/avgd restart \
  && avgcfgctl -w UpdateVir.sched.Task.Disabled=true \
  && avgcfgctl -w Default.setup.daemonize=false \
  && avgcfgctl -w Default.setup.features.antispam=false \
  && avgcfgctl -w Default.setup.features.oad=false \
  && avgcfgctl -w Default.setup.features.scheduler=false \
  && avgcfgctl -w Default.setup.features.tcpd=false \
  && sed -i 's/Severity=INFO/Severity=None/g' /opt/avg/av/cfg/scand.ini \
  && sed -i 's/Severity=INFO/Severity=None/g' /opt/avg/av/cfg/tcpd.ini \
  && sed -i 's/Severity=INFO/Severity=None/g' /opt/avg/av/cfg/wd.ini \
  && echo "===> Clean up unnecessary files..." \
  && apt-get purge -y --auto-remove $buildDeps && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.gnupg

# Ensure ca-certificates is installed for elasticsearch to use https
RUN apt-get update -qq && apt-get install -yq --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Update AVG Definitions
RUN mkdir -p /opt/malice && /etc/init.d/avgd restart && avgupdate

# Add EICAR Test Virus File to malware folder
ADD http://www.eicar.org/download/eicar.com.txt /malware/EICAR

COPY --from=go_builder /bin/avscan /bin/avscan

WORKDIR /malware

ENTRYPOINT ["/bin/avscan"]
CMD ["--help"]
