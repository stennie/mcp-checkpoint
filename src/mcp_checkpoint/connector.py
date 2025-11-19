import asyncio
import logging
from typing import List, Optional, Tuple, Any, Callable, Dict

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from .security_utils import (
    MCPServerInfo,
    ToolInfo,
    ResourceInfo,
    PromptInfo,
    ResourceTemplateInfo,
    TransportType
)

logger = logging.getLogger(__name__)


class MCPConnector:

    async def _close_client_safely(self, client: Client, server_name: str):
        try:
            await client.__aexit__(None, None, None)
        except Exception as e:
            logger.warning(f"Error closing client for {server_name}: {e}")
    
    async def connect_to_server(self, server: MCPServerInfo, progress: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Optional[Client]:
        try:
            transport = self._build_transport(server)

            use_oauth = not (server.headers and any(
                key.lower() == 'authorization' for key in server.headers.keys()
            ))

            connected_flag = asyncio.Event()
            
            watchdog_task = None
            if use_oauth:
                async def _oauth_watchdog():
                    try:
                        await asyncio.sleep(5)
                        if not connected_flag.is_set() and progress:
                            progress('oauth_wait', {"server": server.name})
                    except Exception:
                        pass

                watchdog_task = asyncio.create_task(_oauth_watchdog())

            client = Client(transport)
            await client.__aenter__()

            connected_flag.set()
            if watchdog_task:
                try:
                    watchdog_task.cancel()
                except Exception:
                    pass
            
            logger.info(f"Connected to {server.type.value} server: {server.name}")
            if progress:
                try:
                    progress('oauth_approved', {"server": server.name})
                except Exception:
                    pass
            return client
            
        except Exception as e:
            if watchdog_task:
                try:
                    watchdog_task.cancel()
                except Exception:
                    pass
            logger.error(f"Failed to connect to {server.name}: {e}", exc_info=False)
            return None

    def _build_transport(self, server: MCPServerInfo):
        if server.type == TransportType.STDIO:
            return {
                "mcpServers": {
                    server.name: {
                        "command": server.command,
                        "args": server.args or [],
                        "env": server.env or {}
                    }
                }
            }

        elif server.type in [TransportType.HTTP, TransportType.SSE]:
            if server.endpoint:
                has_auth_header = server.headers and any(
                    key.lower() == 'authorization' for key in server.headers.keys()
                )

                if has_auth_header:
                    return StreamableHttpTransport(
                        url=server.endpoint,
                        headers=server.headers
                    )
                else:
                    return StreamableHttpTransport(
                        url=server.endpoint,
                        auth="oauth"
                    )
            elif server.command and server.args and 'mcp-remote' in server.args:
                mcp_remote_index = server.args.index('mcp-remote')
                if mcp_remote_index + 1 < len(server.args):
                    remote_url = server.args[mcp_remote_index + 1]
                    logger.info(f"Server '{server.name}' using mcp-remote with URL: {remote_url}")
                return {
                    "mcpServers": {
                        server.name: {
                            "command": server.command,
                            "args": server.args or [],
                            "env": server.env or {}
                        }
                    }
                }
            else:
                raise ValueError(
                    f"HTTP/SSE server '{server.name}' has no endpoint URL and is not using mcp-remote. "
                    f"Please provide either an 'endpoint'/'url' field or configure mcp-remote in args."
                )

        else:
            raise ValueError(f"Unsupported transport type: {server.type}")

    def _get_server_endpoint(self, server: MCPServerInfo) -> str:
        if server.type == TransportType.STDIO:
            if server.command:
                return f"stdio://{server.command}"
            else:
                return "stdio://unknown"

        elif server.type == TransportType.HTTP:
            if server.endpoint:
                return server.endpoint

            if server.args and 'mcp-remote' in server.args:
                for i, arg in enumerate(server.args):
                    if arg == 'mcp-remote' and i + 1 < len(server.args):
                        remote_url = server.args[i + 1]
                        return remote_url

            return "http://unknown"

        elif server.type == TransportType.SSE:
            if server.endpoint:
                return server.endpoint
            return "sse://unknown"

        else:
            return "unknown"

    def _convert_tool(self, mcp_tool: Any, server: MCPServerInfo) -> ToolInfo:
        endpoint = self._get_server_endpoint(server)

        tags = []
        meta = getattr(mcp_tool, 'meta', None) or getattr(mcp_tool, '_meta', None)
        if meta and isinstance(meta, dict):
            fastmcp_meta = meta.get('_fastmcp', {})
            if isinstance(fastmcp_meta, dict):
                extracted_tags = fastmcp_meta.get('tags', [])
                if isinstance(extracted_tags, list):
                    tags = [str(tag) for tag in extracted_tags if tag is not None]

        output_schema = None
        try:
            output_schema = getattr(mcp_tool, 'outputSchema', None)
            if output_schema is not None and not isinstance(output_schema, dict):
                output_schema = None
        except Exception:
            output_schema = None

        return ToolInfo(
            name=mcp_tool.name,
            title=getattr(mcp_tool, 'title', None),
            description=mcp_tool.description or "",
            input_schema=mcp_tool.inputSchema or {},
            output_schema=output_schema,
            tags=tags,
            server_name=server.name,
            server_endpoint=endpoint,
            config_file=server.source_file or ""
        )

    async def discover_all(self, server: MCPServerInfo, progress: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Tuple[
        List[ToolInfo], List[ResourceInfo], List[PromptInfo], List[ResourceTemplateInfo]]:
        client = None
        try:
            client = await self.connect_to_server(server, progress=progress)
            if not client:
                raise RuntimeError(f"Failed to connect to server: {server.name}")

            tools = []
            resources = []
            prompts = []
            resource_templates = []
            
            async def discover_tools():
                try:
                    tools_response = await client.list_tools()
                    tool_list = []
                    for mcp_tool in tools_response:
                        tool = self._convert_tool(mcp_tool, server)
                        tool_list.append(tool)
                    logger.info(f"Discovered {len(tool_list)} tools from {server.name}")
                    return tool_list
                except Exception as e:
                    logger.error(f"Failed to discover tools from {server.name}: {e}")
                    return []

            async def discover_resources():
                try:
                    resources_response = await client.list_resources()
                    resource_list = []
                    for mcp_resource in resources_response:
                        resource = self._convert_resource(mcp_resource, server)
                        resource_list.append(resource)
                    logger.info(f"Discovered {len(resource_list)} resources from {server.name}")
                    return resource_list
                except Exception as e:
                    logger.warning(f"Could not discover resources from {server.name}: {e}")
                    return []

            async def discover_prompts():
                try:
                    prompts_response = await client.list_prompts()
                    prompt_list = []
                    for mcp_prompt in prompts_response:
                        prompt = self._convert_prompt(mcp_prompt, server)
                        prompt_list.append(prompt)
                    logger.info(f"Discovered {len(prompt_list)} prompts from {server.name}")
                    return prompt_list
                except Exception as e:
                    logger.warning(f"Could not discover prompts from {server.name}: {e}")
                    return []

            async def discover_resource_templates():
                try:
                    templates_response = await client.list_resource_templates()
                    template_list = []
                    for mcp_template in templates_response:
                        template = self._convert_resource_template(mcp_template, server)
                        template_list.append(template)
                    logger.info(f"Discovered {len(template_list)} resource templates from {server.name}")
                    return template_list
                except Exception as e:
                    logger.warning(f"Could not discover resource templates from {server.name}: {e}")
                    return []

            tools, resources, prompts, resource_templates = await asyncio.gather(
                discover_tools(),
                discover_resources(),
                discover_prompts(),
                discover_resource_templates()
            )

            return tools, resources, prompts, resource_templates

        finally:
            if client is not None:
                await self._close_client_safely(client, server.name)

    def _convert_resource(self, mcp_resource: Any, server: MCPServerInfo) -> ResourceInfo:
        endpoint = self._get_server_endpoint(server)

        tags = []
        meta = getattr(mcp_resource, 'meta', None) or getattr(mcp_resource, '_meta', None)
        if meta and isinstance(meta, dict):
            fastmcp_meta = meta.get('_fastmcp', {})
            if isinstance(fastmcp_meta, dict):
                extracted_tags = fastmcp_meta.get('tags', [])
                if isinstance(extracted_tags, list):
                    tags = [str(tag) for tag in extracted_tags if tag is not None]

        return ResourceInfo(
            uri=str(mcp_resource.uri),
            name=getattr(mcp_resource, 'name', str(mcp_resource.uri)),
            title=getattr(mcp_resource, 'title', None),
            description=getattr(mcp_resource, 'description', ""),
            mime_type=getattr(mcp_resource, 'mimeType', "text/plain"),
            tags=tags,
            server_name=server.name,
            server_endpoint=endpoint,
            config_file=server.source_file or ""
        )

    def _convert_prompt(self, mcp_prompt: Any, server: MCPServerInfo) -> PromptInfo:
        endpoint = self._get_server_endpoint(server)

        tags = []
        meta = getattr(mcp_prompt, 'meta', None) or getattr(mcp_prompt, '_meta', None)
        if meta and isinstance(meta, dict):
            fastmcp_meta = meta.get('_fastmcp', {})
            if isinstance(fastmcp_meta, dict):
                extracted_tags = fastmcp_meta.get('tags', [])
                if isinstance(extracted_tags, list):
                    tags = [str(tag) for tag in extracted_tags if tag is not None]

        arguments = {}
        try:
            prompt_args = getattr(mcp_prompt, 'arguments', None)
            if prompt_args:
                if isinstance(prompt_args, dict):
                    arguments = prompt_args
                elif isinstance(prompt_args, list):
                    for arg in prompt_args:
                        if hasattr(arg, 'name'):
                            arg_dict = {
                                "name": arg.name,
                                "description": getattr(arg, 'description', None),
                                "required": getattr(arg, 'required', None)
                            }
                            arguments[arg.name] = arg_dict
                        elif isinstance(arg, dict):
                            arguments[arg.get('name', '')] = arg
        except Exception:
            pass

        return PromptInfo(
            name=mcp_prompt.name,
            description=getattr(mcp_prompt, 'description', ""),
            arguments=arguments,
            title=getattr(mcp_prompt, 'title', None),
            tags=tags,
            server_name=server.name,
            server_endpoint=endpoint,
            config_file=server.source_file or ""
        )

    def _convert_resource_template(self, mcp_template: Any, server: MCPServerInfo) -> ResourceTemplateInfo:
        endpoint = self._get_server_endpoint(server)

        tags = []
        meta = getattr(mcp_template, 'meta', None) or getattr(mcp_template, '_meta', None)
        if meta and isinstance(meta, dict):
            fastmcp_meta = meta.get('_fastmcp', {})
            if isinstance(fastmcp_meta, dict):
                extracted_tags = fastmcp_meta.get('tags', [])
                if isinstance(extracted_tags, list):
                    tags = [str(tag) for tag in extracted_tags if tag is not None]

        return ResourceTemplateInfo(
            uri_template=str(mcp_template.uriTemplate),
            name=getattr(mcp_template, 'name', str(mcp_template.uriTemplate)),
            description=getattr(mcp_template, 'description', ""),
            mime_type=getattr(mcp_template, 'mimeType', "text/plain"),
            title=getattr(mcp_template, 'title', None),
            tags=tags,
            server_name=server.name,
            server_endpoint=endpoint,
            config_file=server.source_file or ""
        )