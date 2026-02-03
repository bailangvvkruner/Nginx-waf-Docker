FROM alpine:latest AS builder

# 所有构建步骤放在一个 RUN 指令中，确保变量在同一个 shell 会话中传递
RUN NGINX_VERSION=$(wget -q -O - https://nginx.org/en/download.html | grep -oE 'nginx-[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d'-' -f2) && \
    ZSTD_VERSION=$(wget -q -O - https://github.com/facebook/zstd/releases/latest | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -c2-) && \
    CORERULESET_VERSION=$(wget -q -O - https://api.github.com/repos/coreruleset/coreruleset/releases/latest | grep -oE '"tag_name": "[^"]+' | cut -d'"' -f4 | sed 's/v//') && \
    echo "NGINX_VERSION=${NGINX_VERSION}" > /tmp/versions.txt && \
    echo "ZSTD_VERSION=${ZSTD_VERSION}" >> /tmp/versions.txt && \
    echo "CORERULESET_VERSION=${CORERULESET_VERSION}" >> /tmp/versions.txt && \
    # 安装依赖
    set -eux && \
    apk add --no-cache --no-scripts --virtual .build-deps \
    pcre-dev \
    zlib-dev \
    openssl-dev \
    wget \
    git \
    build-base \
    brotli-dev \
    libxml2-dev \
    libxslt-dev \
    curl-dev \
    yajl-dev \
    lmdb-dev \
    geoip-dev \
    lua-dev \
    automake \
    autoconf \
    libtool \
    pkgconfig \
    linux-headers \
    pcre2-dev && \
    # 设置工作目录
    mkdir -p /usr/src && \
    cd /usr/src && \
    # Download NGINX
    wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxf nginx-${NGINX_VERSION}.tar.gz && \
    rm nginx-${NGINX_VERSION}.tar.gz && \
    # Clone Brotli module
    git clone --recurse-submodules -j8 https://github.com/google/ngx_brotli && \
    # Clone and build ModSecurity
    git clone --depth 1 -b v3.0.14 https://github.com/owasp-modsecurity/ModSecurity.git && \
    cd ModSecurity && \
    git submodule init && \
    git submodule update && \
    ./build.sh && \
    ./configure CXXFLAGS="-include cstdint" && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf ModSecurity && \
    # Clone ModSecurity-nginx connector
    git clone --depth 1 -b v1.0.4 https://github.com/owasp-modsecurity/ModSecurity-nginx.git && \
    # Download and build Zstandard
    wget https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz && \
    tar -xzf zstd-${ZSTD_VERSION}.tar.gz && \
    rm zstd-${ZSTD_VERSION}.tar.gz && \
    cd zstd-${ZSTD_VERSION} && \
    make clean && \
    CFLAGS="-fPIC" make -j$(nproc) && make install && \
    cd .. && \
    rm -rf zstd-${ZSTD_VERSION} && \
    # Clone Zstandard NGINX module
    git clone --depth=10 https://github.com/tokers/zstd-nginx-module.git && \
    # Configure and build NGINX with modules
    cd nginx-${NGINX_VERSION} && \
    ./configure --with-compat \
                --add-dynamic-module=../ngx_brotli \
                --add-dynamic-module=../ModSecurity-nginx \
                --add-dynamic-module=../zstd-nginx-module && \
    make -j$(nproc) modules && \
    # 清理不需要的文件
    cd .. && \
    rm -rf ngx_brotli ModSecurity-nginx zstd-nginx-module && \
    rm -rf nginx-${NGINX_VERSION}/src nginx-${NGINX_VERSION}/man nginx-${NGINX_VERSION}/html





FROM nginx:alpine AS final

# 从 builder 阶段复制版本号信息和编译好的模块
COPY --from=builder /tmp/versions.txt /tmp/versions.txt
COPY --from=builder /usr/src/nginx-*/objs/*.so /etc/nginx/modules/
COPY --from=builder /usr/local/modsecurity/lib/* /usr/lib/

# 所有配置步骤放在一个 RUN 指令中
RUN NGINX_VERSION=$(grep NGINX_VERSION /tmp/versions.txt | cut -d'=' -f2) && \
    CORERULESET_VERSION=$(grep CORERULESET_VERSION /tmp/versions.txt | cut -d'=' -f2) && \
    # 创建配置目录并下载必要文件
    mkdir -p /etc/nginx/modsec/plugins && \
    wget https://github.com/coreruleset/coreruleset/archive/v${CORERULESET_VERSION}.tar.gz && \
    tar -xzf v${CORERULESET_VERSION}.tar.gz --strip-components=1 -C /etc/nginx/modsec && \
    rm -f v${CORERULESET_VERSION}.tar.gz && \
    wget -P /etc/nginx/modsec/plugins https://raw.githubusercontent.com/coreruleset/wordpress-rule-exclusions-plugin/master/plugins/wordpress-rule-exclusions-before.conf && \
    wget -P /etc/nginx/modsec/plugins https://raw.githubusercontent.com/coreruleset/wordpress-rule-exclusions-plugin/master/plugins/wordpress-rule-exclusions-config.conf && \
    wget -P /etc/nginx/modsec/plugins https://raw.githubusercontent.com/kejilion/nginx/main/waf/ldnmp-before.conf && \
    cp /etc/nginx/modsec/crs-setup.conf.example /etc/nginx/modsec/crs-setup.conf && \
    sed -i '320,329s/^#//' /etc/nginx/modsec/crs-setup.conf && \
    sed -i 's/setvar:tx.inbound_anomaly_score_threshold=5/setvar:tx.inbound_anomaly_score_threshold=30/' /etc/nginx/modsec/crs-setup.conf && \
    sed -i 's/setvar:tx.outbound_anomaly_score_threshold=4/setvar:tx.outbound_anomaly_score_threshold=16/' /etc/nginx/modsec/crs-setup.conf && \
    wget https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended -O /etc/nginx/modsec/modsecurity.conf && \
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf && \
    sed -i 's/SecPcreMatchLimit [0-9]\+/SecPcreMatchLimit 20000/' /etc/nginx/modsec/modsecurity.conf && \
    sed -i 's/SecPcreMatchLimitRecursion [0-9]\+/SecPcreMatchLimitRecursion 20000/' /etc/nginx/modsec/modsecurity.conf && \
    sed -i 's/^SecRequestBodyLimit\s\+[0-9]\+/SecRequestBodyLimit 52428800/' /etc/nginx/modsec/modsecurity.conf && \
    sed -i 's/^SecRequestBodyNoFilesLimit\s\+[0-9]\+/SecRequestBodyNoFilesLimit 524288/' /etc/nginx/modsec/modsecurity.conf && \
    sed -i 's/^SecAuditEngine RelevantOnly/SecAuditEngine Off/' /etc/nginx/modsec/modsecurity.conf && \
    echo 'Include /etc/nginx/modsec/crs-setup.conf' >> /etc/nginx/modsec/modsecurity.conf && \
    echo 'Include /etc/nginx/modsec/plugins/*-config.conf' >> /etc/nginx/modsec/modsecurity.conf && \
    echo 'Include /etc/nginx/modsec/plugins/*-before.conf' >> /etc/nginx/modsec/modsecurity.conf && \
    echo 'Include /etc/nginx/modsec/rules/*.conf' >> /etc/nginx/modsec/modsecurity.conf && \
    echo 'Include /etc/nginx/modsec/plugins/*-after.conf' >> /etc/nginx/modsec/modsecurity.conf && \
    apk add --no-cache --no-scripts --virtual .run-deps \
    # 只安装运行时需要的依赖
    # apk add --no-cache \
    lua5.1 \
    pcre \
    yajl && \
    ldconfig /usr/lib && \
    wget https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping -O /etc/nginx/modsec/unicode.mapping && \
    rm -rf /var/cache/apk/*