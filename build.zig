const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    var lib = b.addLibrary(.{
        .name = "curl",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    lib.addIncludePath(b.path("include"));
    lib.addIncludePath(b.path("lib"));

    var cflags: std.array_list.Managed([]const u8) = .init(b.allocator);
    addCDefines(lib, &cflags);
    lib.addCSourceFiles(.{ .files = srcs, .flags = cflags.items });

    const libz_dep = b.dependency("libz", .{
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibrary(libz_dep.artifact("z"));

    const libssh2_dep = b.dependency("libssh2", .{
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibrary(libssh2_dep.artifact("ssh2"));

    const mbedtls_dep = libssh2_dep.builder.dependency("mbedtls", .{
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibrary(mbedtls_dep.artifact("mbedtls"));

    b.installArtifact(lib);
    lib.installHeadersDirectory(b.path("include/curl"), "curl", .{});
}

fn addCDefines(lib: *std.Build.Step.Compile, cflags: *std.array_list.Managed([]const u8)) void {
    cflags.append("-DBUILDING_LIBCURL") catch @panic("OOM");

    // when not building a shared library
    cflags.append("-DCURL_STATICLIB=1") catch @panic("OOM");
    //try exported_defines.append(.{ .key = "CURL_STATICLIB", .value = "1" });

    // disables LDAP
    cflags.append("-DCURL_DISABLE_LDAP=1") catch @panic("OOM");

    // disables LDAPS
    cflags.append("-DCURL_DISABLE_LDAPS=1") catch @panic("OOM");

    // if mbedTLS is enabled
    cflags.append("-DUSE_MBEDTLS=1") catch @panic("OOM");

    // disables alt-svc
    // #undef CURL_DISABLE_ALTSVC

    // disables cookies support
    // #undef CURL_DISABLE_COOKIES

    // disables cryptographic authentication
    // #undef CURL_DISABLE_CRYPTO_AUTH

    // disables DICT
    cflags.append("-DCURL_DISABLE_DICT=1") catch @panic("OOM");

    // disables DNS-over-HTTPS
    // #undef CURL_DISABLE_DOH

    // disables FILE
    cflags.append("-DCURL_DISABLE_FILE=1") catch @panic("OOM");

    // disables FTP
    cflags.append("-DCURL_DISABLE_FTP=1") catch @panic("OOM");

    // disables GOPHER
    cflags.append("-DCURL_DISABLE_GOPHER=1") catch @panic("OOM");

    // disables HSTS support
    // #undef CURL_DISABLE_HSTS

    // disables HTTP
    // #undef CURL_DISABLE_HTTP

    // disables IMAP
    cflags.append("-DCURL_DISABLE_IMAP=1") catch @panic("OOM");

    // disables --libcurl option from the curl tool
    // #undef CURL_DISABLE_LIBCURL_OPTION

    // disables MIME support
    // #undef CURL_DISABLE_MIME

    // disables MQTT
    cflags.append("-DCURL_DISABLE_MQTT=1") catch @panic("OOM");

    // disables netrc parser
    // #undef CURL_DISABLE_NETRC

    // disables NTLM support
    // #undef CURL_DISABLE_NTLM

    // disables date parsing
    // #undef CURL_DISABLE_PARSEDATE

    // disables POP3
    cflags.append("-DCURL_DISABLE_POP3=1") catch @panic("OOM");

    // disables built-in progress meter
    // #undef CURL_DISABLE_PROGRESS_METER

    // disables proxies
    // #undef CURL_DISABLE_PROXY

    // disables RTSP
    cflags.append("-DCURL_DISABLE_RTSP=1") catch @panic("OOM");

    // disables SMB
    cflags.append("-DCURL_DISABLE_SMB=1") catch @panic("OOM");

    // disables SMTP
    cflags.append("-DCURL_DISABLE_SMTP=1") catch @panic("OOM");

    // disables use of socketpair for curl_multi_poll
    // #undef CURL_DISABLE_SOCKETPAIR

    // disables TELNET
    cflags.append("-DCURL_DISABLE_TELNET=1") catch @panic("OOM");

    // disables TFTP
    cflags.append("-DCURL_DISABLE_TFTP=1") catch @panic("OOM");

    // disables verbose strings
    // #undef CURL_DISABLE_VERBOSE_STRINGS

    // Define to 1 if you have the `ssh2' library (-lssh2).
    cflags.append("-DHAVE_LIBSSH2=1") catch @panic("OOM");

    // Define to 1 if you have the <libssh2.h> header file.
    cflags.append("-DHAVE_LIBSSH2_H=1") catch @panic("OOM");

    // if zlib is available
    cflags.append("-DHAVE_LIBZ=1") catch @panic("OOM");

    // if you have the zlib.h header file
    cflags.append("-DHAVE_ZLIB_H=1") catch @panic("OOM");

    if (lib.root_module.resolved_target.?.result.os.tag == .windows) {
        // Define if you want to enable WIN32 threaded DNS lookup
        //cflags.append("-DUSE_THREADS_WIN32=1") catch @panic("OOM");

        return;
    }

    //cflags.append("-Dlibcurl_EXPORTS") catch @panic("OOM");

    cflags.append("-DSTDC_HEADERS") catch @panic("OOM");

    // when building libcurl itself
    // #undef BUILDING_LIBCURL

    // Location of default ca bundle
    // cflags.append("-DCURL_CA_BUNDLE=\"/etc/ssl/certs/ca-certificates.crt\"") catch @panic("OOM");

    // define "1" to use built-in ca store of TLS backend
    // #undef CURL_CA_FALLBACK

    // Location of default ca path
    // cflags.append("-DCURL_CA_PATH=\"/etc/ssl/certs\"") catch @panic("OOM");

    // to make a symbol visible
    cflags.append("-DCURL_EXTERN_SYMBOL=__attribute__ ((__visibility__ (\"default\"))") catch @panic("OOM");
    // Ensure using CURL_EXTERN_SYMBOL is possible
    //#ifndef CURL_EXTERN_SYMBOL
    //lib.defineCMacro("CURL_EXTERN_SYMBOL
    //#endif

    // Allow SMB to work on Windows
    // #undef USE_WIN32_CRYPTO

    // Use Windows LDAP implementation
    // #undef USE_WIN32_LDAP

    // your Entropy Gathering Daemon socket pathname
    // #undef EGD_SOCKET

    // Define if you want to enable IPv6 support
    if (!lib.root_module.resolved_target.?.result.os.tag.isDarwin()) {
        cflags.append("-DENABLE_IPV6=1") catch @panic("OOM");
    }

    // Define to 1 if you have the alarm function.
    cflags.append("-DHAVE_ALARM=1") catch @panic("OOM");

    // Define to 1 if you have the <alloca.h> header file.
    cflags.append("-DHAVE_ALLOCA_H=1") catch @panic("OOM");

    // Define to 1 if you have the <arpa/inet.h> header file.
    cflags.append("-DHAVE_ARPA_INET_H=1") catch @panic("OOM");

    // Define to 1 if you have the <arpa/tftp.h> header file.
    cflags.append("-DHAVE_ARPA_TFTP_H=1") catch @panic("OOM");

    // Define to 1 if you have the <assert.h> header file.
    cflags.append("-DHAVE_ASSERT_H=1") catch @panic("OOM");

    // Define to 1 if you have the `basename' function.
    cflags.append("-DHAVE_BASENAME=1") catch @panic("OOM");

    // Define to 1 if bool is an available type.
    cflags.append("-DHAVE_BOOL_T=1") catch @panic("OOM");

    // Define to 1 if you have the __builtin_available function.
    cflags.append("-DHAVE_BUILTIN_AVAILABLE=1") catch @panic("OOM");

    // Define to 1 if you have the clock_gettime function and monotonic timer.
    cflags.append("-DHAVE_CLOCK_GETTIME_MONOTONIC=1") catch @panic("OOM");

    // Define to 1 if you have the `closesocket' function.
    // #undef HAVE_CLOSESOCKET

    // Define to 1 if you have the `CRYPTO_cleanup_all_ex_data' function.
    // #undef HAVE_CRYPTO_CLEANUP_ALL_EX_DATA

    // Define to 1 if you have the <dlfcn.h> header file.
    cflags.append("-DHAVE_DLFCN_H=1") catch @panic("OOM");

    // Define to 1 if you have the <errno.h> header file.
    cflags.append("-DHAVE_ERRNO_H=1") catch @panic("OOM");

    // Define to 1 if you have the fcntl function.
    cflags.append("-DHAVE_FCNTL=1") catch @panic("OOM");

    // Define to 1 if you have the <fcntl.h> header file.
    cflags.append("-DHAVE_FCNTL_H=1") catch @panic("OOM");

    // Define to 1 if you have a working fcntl O_NONBLOCK function.
    cflags.append("-DHAVE_FCNTL_O_NONBLOCK=1") catch @panic("OOM");

    // Define to 1 if you have the freeaddrinfo function.
    cflags.append("-DHAVE_FREEADDRINFO=1") catch @panic("OOM");

    // Define to 1 if you have the ftruncate function.
    cflags.append("-DHAVE_FTRUNCATE=1") catch @panic("OOM");

    // Define to 1 if you have a working getaddrinfo function.
    cflags.append("-DHAVE_GETADDRINFO=1") catch @panic("OOM");

    // Define to 1 if you have the `geteuid' function.
    cflags.append("-DHAVE_GETEUID=1") catch @panic("OOM");

    // Define to 1 if you have the `getppid' function.
    cflags.append("-DHAVE_GETPPID=1") catch @panic("OOM");

    // Define to 1 if you have the gethostbyname function.
    cflags.append("-DHAVE_GETHOSTBYNAME=1") catch @panic("OOM");

    // Define to 1 if you have the gethostbyname_r function.
    if (!lib.root_module.resolved_target.?.result.os.tag.isDarwin()) {
        cflags.append("-DHAVE_GETHOSTBYNAME_R=1") catch @panic("OOM");
    }

    // gethostbyname_r() takes 3 args
    // #undef HAVE_GETHOSTBYNAME_R_3

    // gethostbyname_r() takes 5 args
    // #undef HAVE_GETHOSTBYNAME_R_5

    // gethostbyname_r() takes 6 args
    cflags.append("-DHAVE_GETHOSTBYNAME_R_6=1") catch @panic("OOM");

    // Define to 1 if you have the gethostname function.
    cflags.append("-DHAVE_GETHOSTNAME=1") catch @panic("OOM");

    // Define to 1 if you have a working getifaddrs function.
    // #undef HAVE_GETIFADDRS

    // Define to 1 if you have the `getpass_r' function.
    // #undef HAVE_GETPASS_R

    // Define to 1 if you have the `getppid' function.
    cflags.append("-DHAVE_GETPPID=1") catch @panic("OOM");

    // Define to 1 if you have the `getprotobyname' function.
    cflags.append("-DHAVE_GETPROTOBYNAME=1") catch @panic("OOM");

    // Define to 1 if you have the `getpeername' function.
    cflags.append("-DHAVE_GETPEERNAME=1") catch @panic("OOM");

    // Define to 1 if you have the `getsockname' function.
    cflags.append("-DHAVE_GETSOCKNAME=1") catch @panic("OOM");

    // Define to 1 if you have the `if_nametoindex' function.
    cflags.append("-DHAVE_IF_NAMETOINDEX=1") catch @panic("OOM");

    // Define to 1 if you have the `getpwuid' function.
    cflags.append("-DHAVE_GETPWUID=1") catch @panic("OOM");

    // Define to 1 if you have the `getpwuid_r' function.
    cflags.append("-DHAVE_GETPWUID_R=1") catch @panic("OOM");

    // Define to 1 if you have the `getrlimit' function.
    cflags.append("-DHAVE_GETRLIMIT=1") catch @panic("OOM");

    // Define to 1 if you have the `gettimeofday' function.
    cflags.append("-DHAVE_GETTIMEOFDAY=1") catch @panic("OOM");

    // Define to 1 if you have a working glibc-style strerror_r function.
    // #undef HAVE_GLIBC_STRERROR_R

    // Define to 1 if you have a working gmtime_r function.
    cflags.append("-DHAVE_GMTIME_R=1") catch @panic("OOM");

    // if you have the gssapi libraries
    // #undef HAVE_GSSAPI

    // Define to 1 if you have the <gssapi/gssapi_generic.h> header file.
    // #undef HAVE_GSSAPI_GSSAPI_GENERIC_H

    // Define to 1 if you have the <gssapi/gssapi.h> header file.
    // #undef HAVE_GSSAPI_GSSAPI_H

    // Define to 1 if you have the <gssapi/gssapi_krb5.h> header file.
    // #undef HAVE_GSSAPI_GSSAPI_KRB5_H

    // if you have the GNU gssapi libraries
    // #undef HAVE_GSSGNU

    // if you have the Heimdal gssapi libraries
    // #undef HAVE_GSSHEIMDAL

    // if you have the MIT gssapi libraries
    // #undef HAVE_GSSMIT

    // Define to 1 if you have the `idna_strerror' function.
    // #undef HAVE_IDNA_STRERROR

    // Define to 1 if you have the `idn_free' function.
    // #undef HAVE_IDN_FREE

    // Define to 1 if you have the <idn-free.h> header file.
    // #undef HAVE_IDN_FREE_H

    // Define to 1 if you have the <ifaddrs.h> header file.
    cflags.append("-DHAVE_IFADDRS_H=1") catch @panic("OOM");

    // Define to 1 if you have the `inet_addr' function.
    cflags.append("-DHAVE_INET_ADDR=1") catch @panic("OOM");

    // Define to 1 if you have a IPv6 capable working inet_ntop function.
    // #undef HAVE_INET_NTOP

    // Define to 1 if you have a IPv6 capable working inet_pton function.
    cflags.append("-DHAVE_INET_PTON=1") catch @panic("OOM");

    // Define to 1 if symbol `sa_family_t' exists
    cflags.append("-DHAVE_SA_FAMILY_T=1") catch @panic("OOM");

    // Define to 1 if symbol `ADDRESS_FAMILY' exists
    // #undef HAVE_ADDRESS_FAMILY

    // Define to 1 if you have the <inttypes.h> header file.
    cflags.append("-DHAVE_INTTYPES_H=1") catch @panic("OOM");

    // Define to 1 if you have the ioctl function.
    cflags.append("-DHAVE_IOCTL=1") catch @panic("OOM");

    // Define to 1 if you have the ioctlsocket function.
    // #undef HAVE_IOCTLSOCKET

    // Define to 1 if you have the IoctlSocket camel case function.
    // #undef HAVE_IOCTLSOCKET_CAMEL

    // Define to 1 if you have a working IoctlSocket camel case FIONBIO function.

    // #undef HAVE_IOCTLSOCKET_CAMEL_FIONBIO

    // Define to 1 if you have a working ioctlsocket FIONBIO function.
    // #undef HAVE_IOCTLSOCKET_FIONBIO

    // Define to 1 if you have a working ioctl FIONBIO function.
    cflags.append("-DHAVE_IOCTL_FIONBIO=1") catch @panic("OOM");

    // Define to 1 if you have a working ioctl SIOCGIFADDR function.
    cflags.append("-DHAVE_IOCTL_SIOCGIFADDR=1") catch @panic("OOM");

    // Define to 1 if you have the <io.h> header file.
    // #undef HAVE_IO_H

    // if you have the Kerberos4 libraries (including -ldes)
    // #undef HAVE_KRB4

    // Define to 1 if you have the `krb_get_our_ip_for_realm' function.
    // #undef HAVE_KRB_GET_OUR_IP_FOR_REALM

    // Define to 1 if you have the <krb.h> header file.
    // #undef HAVE_KRB_H

    // Define to 1 if you have the lber.h header file.
    // #undef HAVE_LBER_H

    // Define to 1 if you have the ldapssl.h header file.
    // #undef HAVE_LDAPSSL_H

    // Define to 1 if you have the ldap.h header file.
    // #undef HAVE_LDAP_H

    // Use LDAPS implementation
    // #undef HAVE_LDAP_SSL

    // Define to 1 if you have the ldap_ssl.h header file.
    // #undef HAVE_LDAP_SSL_H

    // Define to 1 if you have the `ldap_url_parse' function.
    cflags.append("-DHAVE_LDAP_URL_PARSE=1") catch @panic("OOM");

    // Define to 1 if you have the <libgen.h> header file.
    cflags.append("-DHAVE_LIBGEN_H=1") catch @panic("OOM");

    // Define to 1 if you have the `idn2' library (-lidn2).
    // #undef HAVE_LIBIDN2

    // Define to 1 if you have the idn2.h header file.
    cflags.append("-DHAVE_IDN2_H=1") catch @panic("OOM");

    // Define to 1 if you have the `resolv' library (-lresolv).
    // #undef HAVE_LIBRESOLV

    // Define to 1 if you have the `resolve' library (-lresolve).
    // #undef HAVE_LIBRESOLVE

    // Define to 1 if you have the `socket' library (-lsocket).
    // #undef HAVE_LIBSOCKET

    // if brotli is available
    // #undef HAVE_BROTLI

    // if zstd is available
    // #undef HAVE_ZSTD

    // if your compiler supports LL
    cflags.append("-DHAVE_LL=1") catch @panic("OOM");

    // Define to 1 if you have the <locale.h> header file.
    cflags.append("-DHAVE_LOCALE_H=1") catch @panic("OOM");

    // Define to 1 if you have a working localtime_r function.
    cflags.append("-DHAVE_LOCALTIME_R=1") catch @panic("OOM");

    // Define to 1 if the compiler supports the 'long long' data type.
    cflags.append("-DHAVE_LONGLONG=1") catch @panic("OOM");

    // Define to 1 if you have the malloc.h header file.
    cflags.append("-DHAVE_MALLOC_H=1") catch @panic("OOM");

    // Define to 1 if you have the <memory.h> header file.
    cflags.append("-DHAVE_MEMORY_H=1") catch @panic("OOM");

    // Define to 1 if you have the MSG_NOSIGNAL flag.
    if (!lib.root_module.resolved_target.?.result.os.tag.isDarwin()) {
        cflags.append("-DHAVE_MSG_NOSIGNAL=1") catch @panic("OOM");
    }

    // Define to 1 if you have the <netdb.h> header file.
    cflags.append("-DHAVE_NETDB_H=1") catch @panic("OOM");

    // Define to 1 if you have the <netinet/in.h> header file.
    cflags.append("-DHAVE_NETINET_IN_H=1") catch @panic("OOM");

    // Define to 1 if you have the <netinet/tcp.h> header file.
    cflags.append("-DHAVE_NETINET_TCP_H=1") catch @panic("OOM");

    // Define to 1 if you have the <linux/tcp.h> header file.
    if (lib.root_module.resolved_target.?.result.os.tag == .linux) {
        cflags.append("-DHAVE_LINUX_TCP_H=1") catch @panic("OOM");
    }

    // Define to 1 if you have the <net/if.h> header file.
    cflags.append("-DHAVE_NET_IF_H=1") catch @panic("OOM");

    // Define to 1 if NI_WITHSCOPEID exists and works.
    // #undef HAVE_NI_WITHSCOPEID

    // if you have an old MIT gssapi library, lacking GSS_C_NT_HOSTBASED_SERVICE
    // #undef HAVE_OLD_GSSMIT

    // Define to 1 if you have the <pem.h> header file.
    // #undef HAVE_PEM_H

    // Define to 1 if you have the `pipe' function.
    cflags.append("-DHAVE_PIPE=1") catch @panic("OOM");

    // Define to 1 if you have a working poll function.
    cflags.append("-DHAVE_POLL=1") catch @panic("OOM");

    // If you have a fine poll
    cflags.append("-DHAVE_POLL_FINE=1") catch @panic("OOM");

    // Define to 1 if you have the <poll.h> header file.
    cflags.append("-DHAVE_POLL_H=1") catch @panic("OOM");

    // Define to 1 if you have a working POSIX-style strerror_r function.
    cflags.append("-DHAVE_POSIX_STRERROR_R=1") catch @panic("OOM");

    // Define to 1 if you have the <pthread.h> header file
    cflags.append("-DHAVE_PTHREAD_H=1") catch @panic("OOM");

    // Define to 1 if you have the <pwd.h> header file.
    cflags.append("-DHAVE_PWD_H=1") catch @panic("OOM");

    // Define to 1 if you have the `RAND_egd' function.
    // #undef HAVE_RAND_EGD

    // Define to 1 if you have the `RAND_screen' function.
    // #undef HAVE_RAND_SCREEN

    // Define to 1 if you have the `RAND_status' function.
    // #undef HAVE_RAND_STATUS

    // Define to 1 if you have the recv function.
    cflags.append("-DHAVE_RECV=1") catch @panic("OOM");

    // Define to 1 if you have the recvfrom function.
    // #undef HAVE_RECVFROM

    // Define to 1 if you have the select function.
    cflags.append("-DHAVE_SELECT=1") catch @panic("OOM");

    // Define to 1 if you have the send function.
    cflags.append("-DHAVE_SEND=1") catch @panic("OOM");

    // Define to 1 if you have the 'fsetxattr' function.
    cflags.append("-DHAVE_FSETXATTR=1") catch @panic("OOM");

    // fsetxattr() takes 5 args
    cflags.append("-DHAVE_FSETXATTR_5=1") catch @panic("OOM");

    // fsetxattr() takes 6 args
    // #undef HAVE_FSETXATTR_6

    // Define to 1 if you have the <setjmp.h> header file.
    cflags.append("-DHAVE_SETJMP_H=1") catch @panic("OOM");

    // Define to 1 if you have the `setlocale' function.
    cflags.append("-DHAVE_SETLOCALE=1") catch @panic("OOM");

    // Define to 1 if you have the `setmode' function.
    // #undef HAVE_SETMODE

    // Define to 1 if you have the `setrlimit' function.
    cflags.append("-DHAVE_SETRLIMIT=1") catch @panic("OOM");

    // Define to 1 if you have the setsockopt function.
    cflags.append("-DHAVE_SETSOCKOPT=1") catch @panic("OOM");

    // Define to 1 if you have a working setsockopt SO_NONBLOCK function.
    // #undef HAVE_SETSOCKOPT_SO_NONBLOCK

    // Define to 1 if you have the sigaction function.
    cflags.append("-DHAVE_SIGACTION=1") catch @panic("OOM");

    // Define to 1 if you have the siginterrupt function.
    cflags.append("-DHAVE_SIGINTERRUPT=1") catch @panic("OOM");

    // Define to 1 if you have the signal function.
    cflags.append("-DHAVE_SIGNAL=1") catch @panic("OOM");

    // Define to 1 if you have the <signal.h> header file.
    cflags.append("-DHAVE_SIGNAL_H=1") catch @panic("OOM");

    // Define to 1 if you have the sigsetjmp function or macro.
    cflags.append("-DHAVE_SIGSETJMP=1") catch @panic("OOM");

    // Define to 1 if struct sockaddr_in6 has the sin6_scope_id member
    cflags.append("-DHAVE_SOCKADDR_IN6_SIN6_SCOPE_ID=1") catch @panic("OOM");

    // Define to 1 if you have the `socket' function.
    cflags.append("-DHAVE_SOCKET=1") catch @panic("OOM");

    // Define to 1 if you have the <stdbool.h> header file.
    cflags.append("-DHAVE_STDBOOL_H=1") catch @panic("OOM");

    // Define to 1 if you have the <stdint.h> header file.
    cflags.append("-DHAVE_STDINT_H=1") catch @panic("OOM");

    // Define to 1 if you have the <stdio.h> header file.
    cflags.append("-DHAVE_STDIO_H=1") catch @panic("OOM");

    // Define to 1 if you have the <stdlib.h> header file.
    cflags.append("-DHAVE_STDLIB_H=1") catch @panic("OOM");

    // Define to 1 if you have the strcasecmp function.
    cflags.append("-DHAVE_STRCASECMP=1") catch @panic("OOM");

    // Define to 1 if you have the strcasestr function.
    // #undef HAVE_STRCASESTR

    // Define to 1 if you have the strcmpi function.
    // #undef HAVE_STRCMPI

    // Define to 1 if you have the strdup function.
    cflags.append("-DHAVE_STRDUP=1") catch @panic("OOM");

    // Define to 1 if you have the strerror_r function.
    cflags.append("-DHAVE_STRERROR_R=1") catch @panic("OOM");

    // Define to 1 if you have the stricmp function.
    // #undef HAVE_STRICMP

    // Define to 1 if you have the <strings.h> header file.
    cflags.append("-DHAVE_STRINGS_H=1") catch @panic("OOM");

    // Define to 1 if you have the <string.h> header file.
    cflags.append("-DHAVE_STRING_H=1") catch @panic("OOM");

    // Define to 1 if you have the strncmpi function.
    // #undef HAVE_STRNCMPI

    // Define to 1 if you have the strnicmp function.
    // #undef HAVE_STRNICMP

    // Define to 1 if you have the <stropts.h> header file.
    // #undef HAVE_STROPTS_H

    // Define to 1 if you have the strstr function.
    cflags.append("-DHAVE_STRSTR=1") catch @panic("OOM");

    // Define to 1 if you have the strtok_r function.
    cflags.append("-DHAVE_STRTOK_R=1") catch @panic("OOM");

    // Define to 1 if you have the strtoll function.
    cflags.append("-DHAVE_STRTOLL=1") catch @panic("OOM");

    // if struct sockaddr_storage is defined
    cflags.append("-DHAVE_STRUCT_SOCKADDR_STORAGE=1") catch @panic("OOM");

    // Define to 1 if you have the timeval struct.
    cflags.append("-DHAVE_STRUCT_TIMEVAL=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/filio.h> header file.
    // #undef HAVE_SYS_FILIO_H

    // Define to 1 if you have the <sys/ioctl.h> header file.
    cflags.append("-DHAVE_SYS_IOCTL_H=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/param.h> header file.
    cflags.append("-DHAVE_SYS_PARAM_H=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/poll.h> header file.
    cflags.append("-DHAVE_SYS_POLL_H=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/resource.h> header file.
    cflags.append("-DHAVE_SYS_RESOURCE_H=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/select.h> header file.
    cflags.append("-DHAVE_SYS_SELECT_H=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/socket.h> header file.
    cflags.append("-DHAVE_SYS_SOCKET_H=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/sockio.h> header file.
    // #undef HAVE_SYS_SOCKIO_H

    // Define to 1 if you have the <sys/stat.h> header file.
    cflags.append("-DHAVE_SYS_STAT_H=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/time.h> header file.
    cflags.append("-DHAVE_SYS_TIME_H=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/types.h> header file.
    cflags.append("-DHAVE_SYS_TYPES_H=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/uio.h> header file.
    cflags.append("-DHAVE_SYS_UIO_H=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/un.h> header file.
    cflags.append("-DHAVE_SYS_UN_H=1") catch @panic("OOM");

    // Define to 1 if you have the <sys/utime.h> header file.
    // #undef HAVE_SYS_UTIME_H

    // Define to 1 if you have the <termios.h> header file.
    cflags.append("-DHAVE_TERMIOS_H=1") catch @panic("OOM");

    // Define to 1 if you have the <termio.h> header file.
    cflags.append("-DHAVE_TERMIO_H=1") catch @panic("OOM");

    // Define to 1 if you have the <time.h> header file.
    cflags.append("-DHAVE_TIME_H=1") catch @panic("OOM");

    // Define to 1 if you have the <tld.h> header file.
    // #undef HAVE_TLD_H

    // Define to 1 if you have the `tld_strerror' function.
    // #undef HAVE_TLD_STRERROR

    // Define to 1 if you have the `uname' function.
    cflags.append("-DHAVE_UNAME=1") catch @panic("OOM");

    // Define to 1 if you have the <unistd.h> header file.
    cflags.append("-DHAVE_UNISTD_H=1") catch @panic("OOM");

    // Define to 1 if you have the `utime' function.
    cflags.append("-DHAVE_UTIME=1") catch @panic("OOM");

    // Define to 1 if you have the `utimes' function.
    cflags.append("-DHAVE_UTIMES=1") catch @panic("OOM");

    // Define to 1 if you have the <utime.h> header file.
    cflags.append("-DHAVE_UTIME_H=1") catch @panic("OOM");

    // Define to 1 if compiler supports C99 variadic macro style.
    cflags.append("-DHAVE_VARIADIC_MACROS_C99=1") catch @panic("OOM");

    // Define to 1 if compiler supports old gcc variadic macro style.
    cflags.append("-DHAVE_VARIADIC_MACROS_GCC=1") catch @panic("OOM");

    // Define to 1 if you have the winber.h header file.
    // #undef HAVE_WINBER_H

    // Define to 1 if you have the windows.h header file.
    // #undef HAVE_WINDOWS_H

    // Define to 1 if you have the winldap.h header file.
    // #undef HAVE_WINLDAP_H

    // Define to 1 if you have the winsock2.h header file.
    // #undef HAVE_WINSOCK2_H

    // Define this symbol if your OS supports changing the contents of argv
    // #undef HAVE_WRITABLE_ARGV

    // Define to 1 if you have the writev function.
    // #undef HAVE_WRITEV

    // Define to 1 if you have the ws2tcpip.h header file.
    // #undef HAVE_WS2TCPIP_H

    // Define to 1 if you have the <x509.h> header file.
    // #undef HAVE_X509_H

    // Define if you have the <process.h> header file.
    // #undef HAVE_PROCESS_H

    // Define to the sub-directory in which libtool stores uninstalled libraries.

    // #undef LT_OBJDIR

    // If you lack a fine basename() prototype
    // #undef NEED_BASENAME_PROTO

    // Define to 1 if you need the lber.h header file even with ldap.h
    // #undef NEED_LBER_H

    // Define to 1 if you need the malloc.h header file even with stdlib.h
    // #undef NEED_MALLOC_H

    // Define to 1 if _REENTRANT preprocessor symbol must be defined.
    // #undef NEED_REENTRANT

    // cpu-machine-OS
    cflags.append("-DOS=\"Linux\"") catch @panic("OOM");

    // Name of package
    // #undef PACKAGE

    // Define to the address where bug reports for this package should be sent.
    // #undef PACKAGE_BUGREPORT

    // Define to the full name of this package.
    // #undef PACKAGE_NAME

    // Define to the full name and version of this package.
    // #undef PACKAGE_STRING

    // Define to the one symbol short name of this package.
    // #undef PACKAGE_TARNAME

    // Define to the version of this package.
    // #undef PACKAGE_VERSION

    // a suitable file to read random data from
    cflags.append("-DRANDOM_FILE=\"/dev/urandom\"") catch @panic("OOM");

    // Define to the type of arg 1 for recvfrom.
    // #undef RECVFROM_TYPE_ARG1

    // Define to the type pointed by arg 2 for recvfrom.
    // #undef RECVFROM_TYPE_ARG2

    // Define to 1 if the type pointed by arg 2 for recvfrom is void.
    // #undef RECVFROM_TYPE_ARG2_IS_VOID

    // Define to the type of arg 3 for recvfrom.
    // #undef RECVFROM_TYPE_ARG3

    // Define to the type of arg 4 for recvfrom.
    // #undef RECVFROM_TYPE_ARG4

    // Define to the type pointed by arg 5 for recvfrom.
    // #undef RECVFROM_TYPE_ARG5

    // Define to 1 if the type pointed by arg 5 for recvfrom is void.
    // #undef RECVFROM_TYPE_ARG5_IS_VOID

    // Define to the type pointed by arg 6 for recvfrom.
    // #undef RECVFROM_TYPE_ARG6

    // Define to 1 if the type pointed by arg 6 for recvfrom is void.
    // #undef RECVFROM_TYPE_ARG6_IS_VOID

    // Define to the function return type for recvfrom.
    // #undef RECVFROM_TYPE_RETV

    // Define to the type of arg 1 for recv.
    cflags.append("-DRECV_TYPE_ARG1=int") catch @panic("OOM");

    // Define to the type of arg 2 for recv.
    cflags.append("-DRECV_TYPE_ARG2=void *") catch @panic("OOM");

    // Define to the type of arg 3 for recv.
    cflags.append("-DRECV_TYPE_ARG3=size_t") catch @panic("OOM");

    // Define to the type of arg 4 for recv.
    cflags.append("-DRECV_TYPE_ARG4=int") catch @panic("OOM");

    // Define to the function return type for recv.
    cflags.append("-DRECV_TYPE_RETV=ssize_t") catch @panic("OOM");

    // Define to the type qualifier of arg 5 for select.
    // #undef SELECT_QUAL_ARG5

    // Define to the type of arg 1 for select.
    // #undef SELECT_TYPE_ARG1

    // Define to the type of args 2, 3 and 4 for select.
    // #undef SELECT_TYPE_ARG234

    // Define to the type of arg 5 for select.
    // #undef SELECT_TYPE_ARG5

    // Define to the function return type for select.
    // #undef SELECT_TYPE_RETV

    // Define to the type qualifier of arg 2 for send.
    cflags.append("-DSEND_QUAL_ARG2=const") catch @panic("OOM");

    // Define to the type of arg 1 for send.
    cflags.append("-DSEND_TYPE_ARG1=int") catch @panic("OOM");

    // Define to the type of arg 2 for send.
    cflags.append("-DSEND_TYPE_ARG2=void *") catch @panic("OOM");

    // Define to the type of arg 3 for send.
    cflags.append("-DSEND_TYPE_ARG3=size_t") catch @panic("OOM");

    // Define to the type of arg 4 for send.
    cflags.append("-DSEND_TYPE_ARG4=int") catch @panic("OOM");

    // Define to the function return type for send.
    cflags.append("-DSEND_TYPE_RETV=ssize_t") catch @panic("OOM");

    // Note: SIZEOF_* variables are fetched with CMake through check_type_size().
    // As per CMake documentation on CheckTypeSize, C preprocessor code is
    // generated by CMake into SIZEOF_*_CODE. This is what we use in the
    // following statements.
    //
    // Reference: https://cmake.org/cmake/help/latest/module/CheckTypeSize.html

    // The size of `int', as computed by sizeof.
    cflags.append("-DSIZEOF_INT=4") catch @panic("OOM");

    // The size of `short', as computed by sizeof.
    cflags.append("-DSIZEOF_SHORT=2") catch @panic("OOM");

    // The size of `long', as computed by sizeof.
    cflags.append("-DSIZEOF_LONG=8") catch @panic("OOM");

    // The size of `off_t', as computed by sizeof.
    cflags.append("-DSIZEOF_OFF_T=8") catch @panic("OOM");

    // The size of `curl_off_t', as computed by sizeof.
    cflags.append("-DSIZEOF_CURL_OFF_T=8") catch @panic("OOM");

    // The size of `size_t', as computed by sizeof.
    cflags.append("-DSIZEOF_SIZE_T=8") catch @panic("OOM");

    // The size of `time_t', as computed by sizeof.
    cflags.append("-DSIZEOF_TIME_T=8") catch @panic("OOM");

    // Define to 1 if you have the ANSI C header files.
    cflags.append("-DSTDC_HEADERS=1") catch @panic("OOM");

    // Define to the type of arg 3 for strerror_r.
    // #undef STRERROR_R_TYPE_ARG3

    // Define to 1 if you can safely include both <sys/time.h> and <time.h>.
    cflags.append("-DTIME_WITH_SYS_TIME=1") catch @panic("OOM");

    // Define if you want to enable c-ares support
    // #undef USE_ARES

    // Define if you want to enable POSIX threaded DNS lookup
    cflags.append("-DUSE_THREADS_POSIX=1") catch @panic("OOM");

    // if libSSH2 is in use
    cflags.append("-DUSE_LIBSSH2=1") catch @panic("OOM");

    // If you want to build curl with the built-in manual
    // #undef USE_MANUAL

    // if NSS is enabled
    // #undef USE_NSS

    // if you have the PK11_CreateManagedGenericObject function
    // #undef HAVE_PK11_CREATEMANAGEDGENERICOBJECT

    // if you want to use OpenLDAP code instead of legacy ldap implementation
    // #undef USE_OPENLDAP

    // to enable NGHTTP2
    // #undef USE_NGHTTP2

    // to enable NGTCP2
    // #undef USE_NGTCP2

    // to enable NGHTTP3
    // #undef USE_NGHTTP3

    // to enable quiche
    // #undef USE_QUICHE

    // Define to 1 if you have the quiche_conn_set_qlog_fd function.
    // #undef HAVE_QUICHE_CONN_SET_QLOG_FD

    // if Unix domain sockets are enabled
    cflags.append("-DUSE_UNIX_SOCKETS") catch @panic("OOM");

    // Define to 1 if you are building a Windows target with large file support.
    // #undef USE_WIN32_LARGE_FILES

    // to enable SSPI support
    // #undef USE_WINDOWS_SSPI

    // to enable Windows SSL
    // #undef USE_SCHANNEL

    // enable multiple SSL backends
    // #undef CURL_WITH_MULTI_SSL

    // Define to 1 if using yaSSL in OpenSSL compatibility mode.
    // #undef USE_YASSLEMUL

    // Version number of package
    // #undef VERSION

    // Define to 1 if OS is AIX.
    //#ifndef _ALL_SOURCE
    //#  undef _ALL_SOURCE
    //#endif

    // Number of bits in a file offset, on hosts where this is settable.
    cflags.append("-D_FILE_OFFSET_BITS=64") catch @panic("OOM");

    // Define for large files, on AIX-style hosts.
    // #undef _LARGE_FILES

    // define this if you need it to compile thread-safe code
    // #undef _THREAD_SAFE

    // Define to empty if `const' does not conform to ANSI C.
    // #undef const

    // Type to use in place of in_addr_t when system does not provide it.
    // #undef in_addr_t

    // Define to `__inline__' or `__inline' if that's what the C compiler
    // calls it, or to nothing if 'inline' is not supported under any name.
    //#ifndef __cplusplus
    //#undef inline
    //#endif

    // Define to `unsigned int' if <sys/types.h> does not define.
    // #undef size_t

    // the signed version of size_t
    // #undef ssize_t

    // Define to 1 if you have the mach_absolute_time function.
    // #undef HAVE_MACH_ABSOLUTE_TIME

    // to enable Windows IDN
    // #undef USE_WIN32_IDN

    // to make the compiler know the prototypes of Windows IDN APIs
    // #undef WANT_IDN_PROTOTYPES
}

const srcs = &.{
    "lib/altsvc.c",
    "lib/amigaos.c",
    "lib/asyn-ares.c",
    "lib/asyn-thread.c",
    "lib/base64.c",
    "lib/bufref.c",
    "lib/c-hyper.c",
    "lib/cf-http.c",
    "lib/cf-socket.c",
    "lib/cfilters.c",
    "lib/conncache.c",
    "lib/connect.c",
    "lib/content_encoding.c",
    "lib/cookie.c",
    "lib/curl_addrinfo.c",
    "lib/curl_des.c",
    "lib/curl_endian.c",
    "lib/curl_fnmatch.c",
    "lib/curl_get_line.c",
    "lib/curl_gethostname.c",
    "lib/curl_gssapi.c",
    "lib/curl_log.c",
    "lib/curl_memrchr.c",
    "lib/curl_multibyte.c",
    "lib/curl_ntlm_core.c",
    "lib/curl_ntlm_wb.c",
    "lib/curl_path.c",
    "lib/curl_range.c",
    "lib/curl_rtmp.c",
    "lib/curl_sasl.c",
    "lib/curl_sspi.c",
    "lib/curl_threads.c",
    "lib/dict.c",
    "lib/doh.c",
    "lib/dynbuf.c",
    "lib/easy.c",
    "lib/easygetopt.c",
    "lib/easyoptions.c",
    "lib/escape.c",
    "lib/file.c",
    "lib/fileinfo.c",
    "lib/fopen.c",
    "lib/formdata.c",
    "lib/ftp.c",
    "lib/ftplistparser.c",
    "lib/getenv.c",
    "lib/getinfo.c",
    "lib/gopher.c",
    "lib/h2h3.c",
    "lib/hash.c",
    "lib/headers.c",
    "lib/hmac.c",
    "lib/hostasyn.c",
    "lib/hostip.c",
    "lib/hostip4.c",
    "lib/hostip6.c",
    "lib/hostsyn.c",
    "lib/hsts.c",
    "lib/http.c",
    "lib/http2.c",
    "lib/http_aws_sigv4.c",
    "lib/http_chunks.c",
    "lib/http_digest.c",
    "lib/http_negotiate.c",
    "lib/http_ntlm.c",
    "lib/http_proxy.c",
    "lib/idn.c",
    "lib/if2ip.c",
    "lib/imap.c",
    "lib/inet_ntop.c",
    "lib/inet_pton.c",
    "lib/krb5.c",
    "lib/ldap.c",
    "lib/llist.c",
    "lib/md4.c",
    "lib/md5.c",
    "lib/memdebug.c",
    "lib/mime.c",
    "lib/mprintf.c",
    "lib/mqtt.c",
    "lib/multi.c",
    "lib/netrc.c",
    "lib/nonblock.c",
    "lib/noproxy.c",
    "lib/openldap.c",
    "lib/parsedate.c",
    "lib/pingpong.c",
    "lib/pop3.c",
    "lib/progress.c",
    "lib/psl.c",
    "lib/rand.c",
    "lib/rename.c",
    "lib/rtsp.c",
    "lib/select.c",
    "lib/sendf.c",
    "lib/setopt.c",
    "lib/sha256.c",
    "lib/share.c",
    "lib/slist.c",
    "lib/smb.c",
    "lib/smtp.c",
    "lib/socketpair.c",
    "lib/socks.c",
    "lib/socks_gssapi.c",
    "lib/socks_sspi.c",
    "lib/speedcheck.c",
    "lib/splay.c",
    "lib/strcase.c",
    "lib/strdup.c",
    "lib/strerror.c",
    "lib/strtok.c",
    "lib/strtoofft.c",
    "lib/system_win32.c",
    "lib/telnet.c",
    "lib/tftp.c",
    "lib/timediff.c",
    "lib/timeval.c",
    "lib/transfer.c",
    "lib/url.c",
    "lib/urlapi.c",
    "lib/vauth/cleartext.c",
    "lib/vauth/cram.c",
    "lib/vauth/digest.c",
    "lib/vauth/digest_sspi.c",
    "lib/vauth/gsasl.c",
    "lib/vauth/krb5_gssapi.c",
    "lib/vauth/krb5_sspi.c",
    "lib/vauth/ntlm.c",
    "lib/vauth/ntlm_sspi.c",
    "lib/vauth/oauth2.c",
    "lib/vauth/spnego_gssapi.c",
    "lib/vauth/spnego_sspi.c",
    "lib/vauth/vauth.c",
    "lib/version.c",
    "lib/version_win32.c",
    "lib/vquic/curl_msh3.c",
    "lib/vquic/curl_ngtcp2.c",
    "lib/vquic/curl_quiche.c",
    "lib/vquic/vquic.c",
    "lib/vssh/libssh.c",
    "lib/vssh/libssh2.c",
    "lib/vssh/wolfssh.c",
    "lib/vtls/bearssl.c",
    "lib/vtls/gskit.c",
    "lib/vtls/gtls.c",
    "lib/vtls/hostcheck.c",
    "lib/vtls/keylog.c",
    "lib/vtls/mbedtls.c",
    "lib/vtls/mbedtls_threadlock.c",
    "lib/vtls/nss.c",
    "lib/vtls/openssl.c",
    "lib/vtls/rustls.c",
    "lib/vtls/schannel.c",
    "lib/vtls/schannel_verify.c",
    "lib/vtls/sectransp.c",
    "lib/vtls/vtls.c",
    "lib/vtls/wolfssl.c",
    "lib/vtls/x509asn1.c",
    "lib/warnless.c",
    "lib/wildcard.c",
    "lib/ws.c",
};
