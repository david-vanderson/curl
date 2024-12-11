const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    var lib = b.addStaticLibrary(.{
        .name = "curl",
        .target = target,
        .optimize = optimize,
    });
    lib.addIncludePath(b.path("include"));
    lib.addIncludePath(b.path("lib"));
    lib.addCSourceFiles(.{ .files = srcs });

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

    addCDefines(lib);

    lib.linkLibC();

    b.installArtifact(lib);
    lib.installHeadersDirectory(b.path("include/curl"), "curl", .{});
}

fn addCDefines(lib: *std.Build.Step.Compile) void {
    lib.defineCMacro("BUILDING_LIBCURL", null);

    // when not building a shared library
    lib.defineCMacro("CURL_STATICLIB", "1");
    //try exported_defines.append(.{ .key = "CURL_STATICLIB", .value = "1" });

    // disables LDAP
    lib.defineCMacro("CURL_DISABLE_LDAP", "1");

    // disables LDAPS
    lib.defineCMacro("CURL_DISABLE_LDAPS", "1");

    // if mbedTLS is enabled
    lib.defineCMacro("USE_MBEDTLS", "1");

    // disables alt-svc
    // #undef CURL_DISABLE_ALTSVC

    // disables cookies support
    // #undef CURL_DISABLE_COOKIES

    // disables cryptographic authentication
    // #undef CURL_DISABLE_CRYPTO_AUTH

    // disables DICT
    lib.defineCMacro("CURL_DISABLE_DICT", "1");

    // disables DNS-over-HTTPS
    // #undef CURL_DISABLE_DOH

    // disables FILE
    lib.defineCMacro("CURL_DISABLE_FILE", "1");

    // disables FTP
    lib.defineCMacro("CURL_DISABLE_FTP", "1");

    // disables GOPHER
    lib.defineCMacro("CURL_DISABLE_GOPHER", "1");

    // disables HSTS support
    // #undef CURL_DISABLE_HSTS

    // disables HTTP
    // #undef CURL_DISABLE_HTTP

    // disables IMAP
    lib.defineCMacro("CURL_DISABLE_IMAP", "1");

    // disables --libcurl option from the curl tool
    // #undef CURL_DISABLE_LIBCURL_OPTION

    // disables MIME support
    // #undef CURL_DISABLE_MIME

    // disables MQTT
    lib.defineCMacro("CURL_DISABLE_MQTT", "1");

    // disables netrc parser
    // #undef CURL_DISABLE_NETRC

    // disables NTLM support
    // #undef CURL_DISABLE_NTLM

    // disables date parsing
    // #undef CURL_DISABLE_PARSEDATE

    // disables POP3
    lib.defineCMacro("CURL_DISABLE_POP3", "1");

    // disables built-in progress meter
    // #undef CURL_DISABLE_PROGRESS_METER

    // disables proxies
    // #undef CURL_DISABLE_PROXY

    // disables RTSP
    lib.defineCMacro("CURL_DISABLE_RTSP", "1");

    // disables SMB
    lib.defineCMacro("CURL_DISABLE_SMB", "1");

    // disables SMTP
    lib.defineCMacro("CURL_DISABLE_SMTP", "1");

    // disables use of socketpair for curl_multi_poll
    // #undef CURL_DISABLE_SOCKETPAIR

    // disables TELNET
    lib.defineCMacro("CURL_DISABLE_TELNET", "1");

    // disables TFTP
    lib.defineCMacro("CURL_DISABLE_TFTP", "1");

    // disables verbose strings
    // #undef CURL_DISABLE_VERBOSE_STRINGS

    // Define to 1 if you have the `ssh2' library (-lssh2).
    lib.defineCMacro("HAVE_LIBSSH2", "1");

    // Define to 1 if you have the <libssh2.h> header file.
    lib.defineCMacro("HAVE_LIBSSH2_H", "1");

    // if zlib is available
    lib.defineCMacro("HAVE_LIBZ", "1");

    // if you have the zlib.h header file
    lib.defineCMacro("HAVE_ZLIB_H", "1");

    if (lib.root_module.resolved_target.?.result.os.tag == .windows) {
        // Define if you want to enable WIN32 threaded DNS lookup
        //lib.defineCMacro("USE_THREADS_WIN32", "1");

        return;
    }

    //lib.defineCMacro("libcurl_EXPORTS", null);

    //lib.defineCMacro("STDC_HEADERS", null);

    // when building libcurl itself
    // #undef BUILDING_LIBCURL

    // Location of default ca bundle
    // lib.defineCMacro("CURL_CA_BUNDLE", "\"/etc/ssl/certs/ca-certificates.crt\"");

    // define "1" to use built-in ca store of TLS backend
    // #undef CURL_CA_FALLBACK

    // Location of default ca path
    // lib.defineCMacro("CURL_CA_PATH", "\"/etc/ssl/certs\"");

    // to make a symbol visible
    lib.defineCMacro("CURL_EXTERN_SYMBOL", "__attribute__ ((__visibility__ (\"default\"))");
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
        lib.defineCMacro("ENABLE_IPV6", "1");
    }

    // Define to 1 if you have the alarm function.
    lib.defineCMacro("HAVE_ALARM", "1");

    // Define to 1 if you have the <alloca.h> header file.
    lib.defineCMacro("HAVE_ALLOCA_H", "1");

    // Define to 1 if you have the <arpa/inet.h> header file.
    lib.defineCMacro("HAVE_ARPA_INET_H", "1");

    // Define to 1 if you have the <arpa/tftp.h> header file.
    lib.defineCMacro("HAVE_ARPA_TFTP_H", "1");

    // Define to 1 if you have the <assert.h> header file.
    lib.defineCMacro("HAVE_ASSERT_H", "1");

    // Define to 1 if you have the `basename' function.
    lib.defineCMacro("HAVE_BASENAME", "1");

    // Define to 1 if bool is an available type.
    lib.defineCMacro("HAVE_BOOL_T", "1");

    // Define to 1 if you have the __builtin_available function.
    lib.defineCMacro("HAVE_BUILTIN_AVAILABLE", "1");

    // Define to 1 if you have the clock_gettime function and monotonic timer.
    lib.defineCMacro("HAVE_CLOCK_GETTIME_MONOTONIC", "1");

    // Define to 1 if you have the `closesocket' function.
    // #undef HAVE_CLOSESOCKET

    // Define to 1 if you have the `CRYPTO_cleanup_all_ex_data' function.
    // #undef HAVE_CRYPTO_CLEANUP_ALL_EX_DATA

    // Define to 1 if you have the <dlfcn.h> header file.
    lib.defineCMacro("HAVE_DLFCN_H", "1");

    // Define to 1 if you have the <errno.h> header file.
    lib.defineCMacro("HAVE_ERRNO_H", "1");

    // Define to 1 if you have the fcntl function.
    lib.defineCMacro("HAVE_FCNTL", "1");

    // Define to 1 if you have the <fcntl.h> header file.
    lib.defineCMacro("HAVE_FCNTL_H", "1");

    // Define to 1 if you have a working fcntl O_NONBLOCK function.
    lib.defineCMacro("HAVE_FCNTL_O_NONBLOCK", "1");

    // Define to 1 if you have the freeaddrinfo function.
    lib.defineCMacro("HAVE_FREEADDRINFO", "1");

    // Define to 1 if you have the ftruncate function.
    lib.defineCMacro("HAVE_FTRUNCATE", "1");

    // Define to 1 if you have a working getaddrinfo function.
    lib.defineCMacro("HAVE_GETADDRINFO", "1");

    // Define to 1 if you have the `geteuid' function.
    lib.defineCMacro("HAVE_GETEUID", "1");

    // Define to 1 if you have the `getppid' function.
    lib.defineCMacro("HAVE_GETPPID", "1");

    // Define to 1 if you have the gethostbyname function.
    lib.defineCMacro("HAVE_GETHOSTBYNAME", "1");

    // Define to 1 if you have the gethostbyname_r function.
    if (!lib.root_module.resolved_target.?.result.os.tag.isDarwin()) {
        lib.defineCMacro("HAVE_GETHOSTBYNAME_R", "1");
    }

    // gethostbyname_r() takes 3 args
    // #undef HAVE_GETHOSTBYNAME_R_3

    // gethostbyname_r() takes 5 args
    // #undef HAVE_GETHOSTBYNAME_R_5

    // gethostbyname_r() takes 6 args
    lib.defineCMacro("HAVE_GETHOSTBYNAME_R_6", "1");

    // Define to 1 if you have the gethostname function.
    lib.defineCMacro("HAVE_GETHOSTNAME", "1");

    // Define to 1 if you have a working getifaddrs function.
    // #undef HAVE_GETIFADDRS

    // Define to 1 if you have the `getpass_r' function.
    // #undef HAVE_GETPASS_R

    // Define to 1 if you have the `getppid' function.
    lib.defineCMacro("HAVE_GETPPID", "1");

    // Define to 1 if you have the `getprotobyname' function.
    lib.defineCMacro("HAVE_GETPROTOBYNAME", "1");

    // Define to 1 if you have the `getpeername' function.
    lib.defineCMacro("HAVE_GETPEERNAME", "1");

    // Define to 1 if you have the `getsockname' function.
    lib.defineCMacro("HAVE_GETSOCKNAME", "1");

    // Define to 1 if you have the `if_nametoindex' function.
    lib.defineCMacro("HAVE_IF_NAMETOINDEX", "1");

    // Define to 1 if you have the `getpwuid' function.
    lib.defineCMacro("HAVE_GETPWUID", "1");

    // Define to 1 if you have the `getpwuid_r' function.
    lib.defineCMacro("HAVE_GETPWUID_R", "1");

    // Define to 1 if you have the `getrlimit' function.
    lib.defineCMacro("HAVE_GETRLIMIT", "1");

    // Define to 1 if you have the `gettimeofday' function.
    lib.defineCMacro("HAVE_GETTIMEOFDAY", "1");

    // Define to 1 if you have a working glibc-style strerror_r function.
    // #undef HAVE_GLIBC_STRERROR_R

    // Define to 1 if you have a working gmtime_r function.
    lib.defineCMacro("HAVE_GMTIME_R", "1");

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
    lib.defineCMacro("HAVE_IFADDRS_H", "1");

    // Define to 1 if you have the `inet_addr' function.
    lib.defineCMacro("HAVE_INET_ADDR", "1");

    // Define to 1 if you have a IPv6 capable working inet_ntop function.
    // #undef HAVE_INET_NTOP

    // Define to 1 if you have a IPv6 capable working inet_pton function.
    lib.defineCMacro("HAVE_INET_PTON", "1");

    // Define to 1 if symbol `sa_family_t' exists
    lib.defineCMacro("HAVE_SA_FAMILY_T", "1");

    // Define to 1 if symbol `ADDRESS_FAMILY' exists
    // #undef HAVE_ADDRESS_FAMILY

    // Define to 1 if you have the <inttypes.h> header file.
    lib.defineCMacro("HAVE_INTTYPES_H", "1");

    // Define to 1 if you have the ioctl function.
    lib.defineCMacro("HAVE_IOCTL", "1");

    // Define to 1 if you have the ioctlsocket function.
    // #undef HAVE_IOCTLSOCKET

    // Define to 1 if you have the IoctlSocket camel case function.
    // #undef HAVE_IOCTLSOCKET_CAMEL

    // Define to 1 if you have a working IoctlSocket camel case FIONBIO function.

    // #undef HAVE_IOCTLSOCKET_CAMEL_FIONBIO

    // Define to 1 if you have a working ioctlsocket FIONBIO function.
    // #undef HAVE_IOCTLSOCKET_FIONBIO

    // Define to 1 if you have a working ioctl FIONBIO function.
    lib.defineCMacro("HAVE_IOCTL_FIONBIO", "1");

    // Define to 1 if you have a working ioctl SIOCGIFADDR function.
    lib.defineCMacro("HAVE_IOCTL_SIOCGIFADDR", "1");

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
    lib.defineCMacro("HAVE_LDAP_URL_PARSE", "1");

    // Define to 1 if you have the <libgen.h> header file.
    lib.defineCMacro("HAVE_LIBGEN_H", "1");

    // Define to 1 if you have the `idn2' library (-lidn2).
    // #undef HAVE_LIBIDN2

    // Define to 1 if you have the idn2.h header file.
    lib.defineCMacro("HAVE_IDN2_H", "1");

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
    lib.defineCMacro("HAVE_LL", "1");

    // Define to 1 if you have the <locale.h> header file.
    lib.defineCMacro("HAVE_LOCALE_H", "1");

    // Define to 1 if you have a working localtime_r function.
    lib.defineCMacro("HAVE_LOCALTIME_R", "1");

    // Define to 1 if the compiler supports the 'long long' data type.
    lib.defineCMacro("HAVE_LONGLONG", "1");

    // Define to 1 if you have the malloc.h header file.
    lib.defineCMacro("HAVE_MALLOC_H", "1");

    // Define to 1 if you have the <memory.h> header file.
    lib.defineCMacro("HAVE_MEMORY_H", "1");

    // Define to 1 if you have the MSG_NOSIGNAL flag.
    if (!lib.root_module.resolved_target.?.result.os.tag.isDarwin()) {
        lib.defineCMacro("HAVE_MSG_NOSIGNAL", "1");
    }

    // Define to 1 if you have the <netdb.h> header file.
    lib.defineCMacro("HAVE_NETDB_H", "1");

    // Define to 1 if you have the <netinet/in.h> header file.
    lib.defineCMacro("HAVE_NETINET_IN_H", "1");

    // Define to 1 if you have the <netinet/tcp.h> header file.
    lib.defineCMacro("HAVE_NETINET_TCP_H", "1");

    // Define to 1 if you have the <linux/tcp.h> header file.
    if (lib.root_module.resolved_target.?.result.os.tag == .linux) {
        lib.defineCMacro("HAVE_LINUX_TCP_H", "1");
    }

    // Define to 1 if you have the <net/if.h> header file.
    lib.defineCMacro("HAVE_NET_IF_H", "1");

    // Define to 1 if NI_WITHSCOPEID exists and works.
    // #undef HAVE_NI_WITHSCOPEID

    // if you have an old MIT gssapi library, lacking GSS_C_NT_HOSTBASED_SERVICE
    // #undef HAVE_OLD_GSSMIT

    // Define to 1 if you have the <pem.h> header file.
    // #undef HAVE_PEM_H

    // Define to 1 if you have the `pipe' function.
    lib.defineCMacro("HAVE_PIPE", "1");

    // Define to 1 if you have a working poll function.
    lib.defineCMacro("HAVE_POLL", "1");

    // If you have a fine poll
    lib.defineCMacro("HAVE_POLL_FINE", "1");

    // Define to 1 if you have the <poll.h> header file.
    lib.defineCMacro("HAVE_POLL_H", "1");

    // Define to 1 if you have a working POSIX-style strerror_r function.
    lib.defineCMacro("HAVE_POSIX_STRERROR_R", "1");

    // Define to 1 if you have the <pthread.h> header file
    lib.defineCMacro("HAVE_PTHREAD_H", "1");

    // Define to 1 if you have the <pwd.h> header file.
    lib.defineCMacro("HAVE_PWD_H", "1");

    // Define to 1 if you have the `RAND_egd' function.
    // #undef HAVE_RAND_EGD

    // Define to 1 if you have the `RAND_screen' function.
    // #undef HAVE_RAND_SCREEN

    // Define to 1 if you have the `RAND_status' function.
    // #undef HAVE_RAND_STATUS

    // Define to 1 if you have the recv function.
    lib.defineCMacro("HAVE_RECV", "1");

    // Define to 1 if you have the recvfrom function.
    // #undef HAVE_RECVFROM

    // Define to 1 if you have the select function.
    lib.defineCMacro("HAVE_SELECT", "1");

    // Define to 1 if you have the send function.
    lib.defineCMacro("HAVE_SEND", "1");

    // Define to 1 if you have the 'fsetxattr' function.
    lib.defineCMacro("HAVE_FSETXATTR", "1");

    // fsetxattr() takes 5 args
    lib.defineCMacro("HAVE_FSETXATTR_5", "1");

    // fsetxattr() takes 6 args
    // #undef HAVE_FSETXATTR_6

    // Define to 1 if you have the <setjmp.h> header file.
    lib.defineCMacro("HAVE_SETJMP_H", "1");

    // Define to 1 if you have the `setlocale' function.
    lib.defineCMacro("HAVE_SETLOCALE", "1");

    // Define to 1 if you have the `setmode' function.
    // #undef HAVE_SETMODE

    // Define to 1 if you have the `setrlimit' function.
    lib.defineCMacro("HAVE_SETRLIMIT", "1");

    // Define to 1 if you have the setsockopt function.
    lib.defineCMacro("HAVE_SETSOCKOPT", "1");

    // Define to 1 if you have a working setsockopt SO_NONBLOCK function.
    // #undef HAVE_SETSOCKOPT_SO_NONBLOCK

    // Define to 1 if you have the sigaction function.
    lib.defineCMacro("HAVE_SIGACTION", "1");

    // Define to 1 if you have the siginterrupt function.
    lib.defineCMacro("HAVE_SIGINTERRUPT", "1");

    // Define to 1 if you have the signal function.
    lib.defineCMacro("HAVE_SIGNAL", "1");

    // Define to 1 if you have the <signal.h> header file.
    lib.defineCMacro("HAVE_SIGNAL_H", "1");

    // Define to 1 if you have the sigsetjmp function or macro.
    lib.defineCMacro("HAVE_SIGSETJMP", "1");

    // Define to 1 if struct sockaddr_in6 has the sin6_scope_id member
    lib.defineCMacro("HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID", "1");

    // Define to 1 if you have the `socket' function.
    lib.defineCMacro("HAVE_SOCKET", "1");

    // Define to 1 if you have the <stdbool.h> header file.
    lib.defineCMacro("HAVE_STDBOOL_H", "1");

    // Define to 1 if you have the <stdint.h> header file.
    lib.defineCMacro("HAVE_STDINT_H", "1");

    // Define to 1 if you have the <stdio.h> header file.
    lib.defineCMacro("HAVE_STDIO_H", "1");

    // Define to 1 if you have the <stdlib.h> header file.
    lib.defineCMacro("HAVE_STDLIB_H", "1");

    // Define to 1 if you have the strcasecmp function.
    lib.defineCMacro("HAVE_STRCASECMP", "1");

    // Define to 1 if you have the strcasestr function.
    // #undef HAVE_STRCASESTR

    // Define to 1 if you have the strcmpi function.
    // #undef HAVE_STRCMPI

    // Define to 1 if you have the strdup function.
    lib.defineCMacro("HAVE_STRDUP", "1");

    // Define to 1 if you have the strerror_r function.
    lib.defineCMacro("HAVE_STRERROR_R", "1");

    // Define to 1 if you have the stricmp function.
    // #undef HAVE_STRICMP

    // Define to 1 if you have the <strings.h> header file.
    lib.defineCMacro("HAVE_STRINGS_H", "1");

    // Define to 1 if you have the <string.h> header file.
    lib.defineCMacro("HAVE_STRING_H", "1");

    // Define to 1 if you have the strncmpi function.
    // #undef HAVE_STRNCMPI

    // Define to 1 if you have the strnicmp function.
    // #undef HAVE_STRNICMP

    // Define to 1 if you have the <stropts.h> header file.
    // #undef HAVE_STROPTS_H

    // Define to 1 if you have the strstr function.
    lib.defineCMacro("HAVE_STRSTR", "1");

    // Define to 1 if you have the strtok_r function.
    lib.defineCMacro("HAVE_STRTOK_R", "1");

    // Define to 1 if you have the strtoll function.
    lib.defineCMacro("HAVE_STRTOLL", "1");

    // if struct sockaddr_storage is defined
    lib.defineCMacro("HAVE_STRUCT_SOCKADDR_STORAGE", "1");

    // Define to 1 if you have the timeval struct.
    lib.defineCMacro("HAVE_STRUCT_TIMEVAL", "1");

    // Define to 1 if you have the <sys/filio.h> header file.
    // #undef HAVE_SYS_FILIO_H

    // Define to 1 if you have the <sys/ioctl.h> header file.
    lib.defineCMacro("HAVE_SYS_IOCTL_H", "1");

    // Define to 1 if you have the <sys/param.h> header file.
    lib.defineCMacro("HAVE_SYS_PARAM_H", "1");

    // Define to 1 if you have the <sys/poll.h> header file.
    lib.defineCMacro("HAVE_SYS_POLL_H", "1");

    // Define to 1 if you have the <sys/resource.h> header file.
    lib.defineCMacro("HAVE_SYS_RESOURCE_H", "1");

    // Define to 1 if you have the <sys/select.h> header file.
    lib.defineCMacro("HAVE_SYS_SELECT_H", "1");

    // Define to 1 if you have the <sys/socket.h> header file.
    lib.defineCMacro("HAVE_SYS_SOCKET_H", "1");

    // Define to 1 if you have the <sys/sockio.h> header file.
    // #undef HAVE_SYS_SOCKIO_H

    // Define to 1 if you have the <sys/stat.h> header file.
    lib.defineCMacro("HAVE_SYS_STAT_H", "1");

    // Define to 1 if you have the <sys/time.h> header file.
    lib.defineCMacro("HAVE_SYS_TIME_H", "1");

    // Define to 1 if you have the <sys/types.h> header file.
    lib.defineCMacro("HAVE_SYS_TYPES_H", "1");

    // Define to 1 if you have the <sys/uio.h> header file.
    lib.defineCMacro("HAVE_SYS_UIO_H", "1");

    // Define to 1 if you have the <sys/un.h> header file.
    lib.defineCMacro("HAVE_SYS_UN_H", "1");

    // Define to 1 if you have the <sys/utime.h> header file.
    // #undef HAVE_SYS_UTIME_H

    // Define to 1 if you have the <termios.h> header file.
    lib.defineCMacro("HAVE_TERMIOS_H", "1");

    // Define to 1 if you have the <termio.h> header file.
    lib.defineCMacro("HAVE_TERMIO_H", "1");

    // Define to 1 if you have the <time.h> header file.
    lib.defineCMacro("HAVE_TIME_H", "1");

    // Define to 1 if you have the <tld.h> header file.
    // #undef HAVE_TLD_H

    // Define to 1 if you have the `tld_strerror' function.
    // #undef HAVE_TLD_STRERROR

    // Define to 1 if you have the `uname' function.
    lib.defineCMacro("HAVE_UNAME", "1");

    // Define to 1 if you have the <unistd.h> header file.
    lib.defineCMacro("HAVE_UNISTD_H", "1");

    // Define to 1 if you have the `utime' function.
    lib.defineCMacro("HAVE_UTIME", "1");

    // Define to 1 if you have the `utimes' function.
    lib.defineCMacro("HAVE_UTIMES", "1");

    // Define to 1 if you have the <utime.h> header file.
    lib.defineCMacro("HAVE_UTIME_H", "1");

    // Define to 1 if compiler supports C99 variadic macro style.
    lib.defineCMacro("HAVE_VARIADIC_MACROS_C99", "1");

    // Define to 1 if compiler supports old gcc variadic macro style.
    lib.defineCMacro("HAVE_VARIADIC_MACROS_GCC", "1");

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
    lib.defineCMacro("OS", "\"Linux\"");

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
    lib.defineCMacro("RANDOM_FILE", "\"/dev/urandom\"");

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
    lib.defineCMacro("RECV_TYPE_ARG1", "int");

    // Define to the type of arg 2 for recv.
    lib.defineCMacro("RECV_TYPE_ARG2", "void *");

    // Define to the type of arg 3 for recv.
    lib.defineCMacro("RECV_TYPE_ARG3", "size_t");

    // Define to the type of arg 4 for recv.
    lib.defineCMacro("RECV_TYPE_ARG4", "int");

    // Define to the function return type for recv.
    lib.defineCMacro("RECV_TYPE_RETV", "ssize_t");

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
    lib.defineCMacro("SEND_QUAL_ARG2", "const");

    // Define to the type of arg 1 for send.
    lib.defineCMacro("SEND_TYPE_ARG1", "int");

    // Define to the type of arg 2 for send.
    lib.defineCMacro("SEND_TYPE_ARG2", "void *");

    // Define to the type of arg 3 for send.
    lib.defineCMacro("SEND_TYPE_ARG3", "size_t");

    // Define to the type of arg 4 for send.
    lib.defineCMacro("SEND_TYPE_ARG4", "int");

    // Define to the function return type for send.
    lib.defineCMacro("SEND_TYPE_RETV", "ssize_t");

    // Note: SIZEOF_* variables are fetched with CMake through check_type_size().
    // As per CMake documentation on CheckTypeSize, C preprocessor code is
    // generated by CMake into SIZEOF_*_CODE. This is what we use in the
    // following statements.
    //
    // Reference: https://cmake.org/cmake/help/latest/module/CheckTypeSize.html

    // The size of `int', as computed by sizeof.
    lib.defineCMacro("SIZEOF_INT", "4");

    // The size of `short', as computed by sizeof.
    lib.defineCMacro("SIZEOF_SHORT", "2");

    // The size of `long', as computed by sizeof.
    lib.defineCMacro("SIZEOF_LONG", "8");

    // The size of `off_t', as computed by sizeof.
    lib.defineCMacro("SIZEOF_OFF_T", "8");

    // The size of `curl_off_t', as computed by sizeof.
    lib.defineCMacro("SIZEOF_CURL_OFF_T", "8");

    // The size of `size_t', as computed by sizeof.
    lib.defineCMacro("SIZEOF_SIZE_T", "8");

    // The size of `time_t', as computed by sizeof.
    lib.defineCMacro("SIZEOF_TIME_T", "8");

    // Define to 1 if you have the ANSI C header files.
    lib.defineCMacro("STDC_HEADERS", "1");

    // Define to the type of arg 3 for strerror_r.
    // #undef STRERROR_R_TYPE_ARG3

    // Define to 1 if you can safely include both <sys/time.h> and <time.h>.
    lib.defineCMacro("TIME_WITH_SYS_TIME", "1");

    // Define if you want to enable c-ares support
    // #undef USE_ARES

    // Define if you want to enable POSIX threaded DNS lookup
    lib.defineCMacro("USE_THREADS_POSIX", "1");

    // if libSSH2 is in use
    lib.defineCMacro("USE_LIBSSH2", "1");

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
    lib.defineCMacro("USE_UNIX_SOCKETS", null);

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
    lib.defineCMacro("_FILE_OFFSET_BITS", "64");

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
