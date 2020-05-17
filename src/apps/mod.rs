/*! Application-layer protocols.

The `apps` module deals with *application-layer protocols*. It contains the
communications protocols used in process-to-process communications across an
IP computer network. Examples include [SSH], [FTP], [SNTP], [HTTP] etc.

[SSH]: https://en.wikipedia.org/wiki/Secure_Shell
[FTP]: https://en.wikipedia.org/wiki/File_Transfer_Protocol
[SNTP]: https://en.wikipedia.org/wiki/Network_Time_Protocol#SNTP
[HTTP]: https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
*/

#[cfg(feature = "app-sntp")]
pub mod sntp;
