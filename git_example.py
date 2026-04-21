import marimo

__generated_with = "0.23.2"
app = marimo.App(width="medium")


@app.cell
def _():
    import io
    import paramiko
    import paramiko.client
    import paramiko.config
    import dulwich
    import dulwich.porcelain as git
    #from dulwich.contrib.paramiko_vendor import ParamikoSSHVendor
    return dulwich, git, io, paramiko


@app.cell
def _(git):
    print(git.status())
    return


@app.cell
def _(git, io):
    buf = io.BytesIO()
    git.diff(paths=['pyproject.toml'], outstream=buf)
    print(buf.getbuffer().tobytes().decode('utf-8'))
    return


@app.cell
def _(git):
    git.add(paths=['git_example.py', 'pyproject.toml', 'uv.lock'])
    git.commit(message='Example git workflow')
    return


@app.cell
def _(paramiko):
    import os
    import warnings
    from typing import Any, BinaryIO, cast

    class _ParamikoWrapper:
        """Wrapper for paramiko SSH channel to provide a file-like interface."""

        def __init__(self, client: paramiko.SSHClient, channel: paramiko.Channel) -> None:
            """Initialize the paramiko wrapper.

            Args:
                client: The SSH client instance
                channel: The SSH channel for communication
            """
            self.client = client
            self.channel = channel

            # Channel must block
            self.channel.setblocking(True)

        @property
        def stderr(self) -> BinaryIO:
            """Get stderr stream from the channel.

            Returns:
                Binary IO stream for stderr
            """
            return cast(BinaryIO, self.channel.makefile_stderr("rb"))

        def can_read(self) -> bool:
            """Check if data is available to read.

            Returns:
                True if data is available
            """
            return self.channel.recv_ready()

        def write(self, data: bytes) -> None:
            """Write data to the channel.

            Args:
                data: Bytes to write
            """
            return self.channel.sendall(data)

        def read(self, n: int | None = None) -> bytes:
            """Read data from the channel.

            Args:
                n: Number of bytes to read (default: 4096)

            Returns:
                Bytes read from the channel
            """
            data = self.channel.recv(n or 4096)
            data_len = len(data)

            # Closed socket
            if not data:
                return b""

            # Read more if needed
            if n and data_len < n:
                diff_len = n - data_len
                return data + self.read(diff_len)
            return data

        def close(self) -> None:
            """Close the SSH channel."""
            self.channel.close()


    class ParamikoSSHVendor:
        """SSH vendor implementation using paramiko."""

        # http://docs.paramiko.org/en/2.4/api/client.html

        def __init__(self, **kwargs: object) -> None:
            """Initialize the paramiko SSH vendor.

            Args:
                **kwargs: Additional keyword arguments passed to SSHClient
            """
            self.kwargs = kwargs
            self.ssh_config = self._load_ssh_config()

        def _load_ssh_config(self) -> paramiko.config.SSHConfig:
            """Load SSH configuration from ~/.ssh/config."""
            ssh_config = paramiko.config.SSHConfig()
            config_path = os.path.expanduser("~/.ssh/config")
            try:
                with open(config_path) as config_file:
                    ssh_config.parse(config_file)
            except FileNotFoundError:
                # Config file doesn't exist - this is normal, ignore silently
                pass
            except (OSError, PermissionError) as e:
                # Config file exists but can't be read - warn user
                warnings.warn(f"Could not read SSH config file {config_path}: {e}")
            return ssh_config

        def _load_host_keys(
            self, client: paramiko.SSHClient, host_config: paramiko.config.SSHConfigDict
        ) -> None:
            """Load host keys before connecting.

            This keeps the vendor fail-closed by default while still honoring
            SSH config overrides for known_hosts paths when present.
            """
            client.load_system_host_keys()

            for config_key in ("globalknownhostsfile", "userknownhostsfile"):
                known_hosts_paths = host_config.get(config_key)
                if isinstance(known_hosts_paths, str):
                    known_hosts_paths = [known_hosts_paths]
                if not known_hosts_paths:
                    continue

                for known_hosts_path in known_hosts_paths:
                    expanded_path = os.path.expanduser(known_hosts_path)
                    try:
                        client.load_host_keys(expanded_path)
                    except FileNotFoundError:
                        continue
                    except (OSError, PermissionError) as e:
                        warnings.warn(
                            f"Could not read known hosts file {expanded_path}: {e}"
                        )

        def run_command(
            self,
            host: str,
            command: bytes,
            username: str | None = None,
            port: int | None = None,
            password: str | None = None,
            pkey: paramiko.PKey | None = None,
            key_filename: str | None = None,
            ssh_command: str | None = None,
            protocol_version: int | None = None,
            **kwargs: object,
        ) -> _ParamikoWrapper:
            """Run a command on a remote host via SSH.

            Args:
                host: Hostname to connect to
                command: Command to execute (as bytes)
                username: SSH username (optional)
                port: SSH port (optional)
                password: SSH password (optional)
                pkey: Private key for authentication (optional)
                key_filename: Path to private key file (optional)
                ssh_command: SSH command (ignored - Paramiko doesn't use external SSH)
                protocol_version: SSH protocol version (optional)
                **kwargs: Additional keyword arguments

            Returns:
                _ParamikoWrapper instance for the SSH channel
            """
            # Convert bytes command to str for paramiko
            command_str = command.decode("utf-8")

            client = paramiko.SSHClient()

            # Get SSH config for this host
            host_config = self.ssh_config.lookup(host)

            connection_kwargs: dict[str, Any] = {
                "hostname": host_config.get("hostname", host)
            }
            connection_kwargs.update(self.kwargs)

            # Use SSH config values if not explicitly provided
            if username:
                connection_kwargs["username"] = username
            elif "user" in host_config:
                connection_kwargs["username"] = host_config["user"]

            if port:
                connection_kwargs["port"] = port
            elif "port" in host_config:
                connection_kwargs["port"] = int(host_config["port"])

            if password:
                connection_kwargs["password"] = password
            if pkey:
                connection_kwargs["pkey"] = pkey
            if key_filename:
                connection_kwargs["key_filename"] = key_filename
            elif "identityfile" in host_config:
                # Use the first identity file from SSH config
                identity_files = host_config["identityfile"]
                if isinstance(identity_files, list) and identity_files:
                    connection_kwargs["key_filename"] = identity_files[0]
                elif isinstance(identity_files, str):
                    connection_kwargs["key_filename"] = identity_files

            connection_kwargs.update(kwargs)

            self._load_host_keys(client, host_config)
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(**connection_kwargs)

            # Open SSH session
            transport = client.get_transport()
            if transport is None:
                raise RuntimeError("Transport is None")
            channel = transport.open_session()

            if protocol_version is None or protocol_version == 2:
                channel.set_environment_variable(name="GIT_PROTOCOL", value="version=2")

            # Run commands
            channel.exec_command(command_str)

            return _ParamikoWrapper(client, channel)

    return (ParamikoSSHVendor,)


@app.cell
def _(ParamikoSSHVendor, dulwich, io, paramiko):
    pem = '''actual-pem-here'''
    private_key = paramiko.Ed25519Key(file_obj=io.StringIO(pem))
    def get_dulwich_ssh_vendor():
        vendor = ParamikoSSHVendor(pkey=private_key)
        return vendor
    dulwich.client.get_ssh_vendor = get_dulwich_ssh_vendor
    return


@app.cell
def _(git):
    git.push(repo='.')
    return


@app.cell
def _():
    import marimo as mo

    return (mo,)


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    TODOs:
    - strategy to push ssh key
    - load ssh host key(s)
    - load ParamikoSSHVendor from dulwich.contrib
    """)
    return


if __name__ == "__main__":
    app.run()
