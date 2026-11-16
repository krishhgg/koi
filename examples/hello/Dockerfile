# The smallest preview koi can run: a static page served on 8080 by a non-root
# user. Used by the daemon's Docker integration test and as the first preview
# on the box.
FROM busybox:1.37
RUN mkdir -p /www \
	&& printf '<!doctype html><title>hello from koi</title><h1>hello from koi</h1>\n' > /www/index.html
USER 65534:65534
EXPOSE 8080
CMD ["httpd", "-f", "-v", "-p", "8080", "-h", "/www"]
