require"splay.base"
rpc = require"splay.rpc"

function call_me(position)
  log:print("I received an RPC from node "..position)
end

events.run(function()
  log:print("server", rpc.server(job.me.port))
  events.sleep(5)
  log:print("I'm "..job.me.ip..":"..job.me.port)
  log:print("My position in the list is: "..job.position)
  log:print("List type is '"..job.list_type.."' with "..#job.nodes.." nodes")
  log:print("### I am calling node "..job.nodes[1].ip..":"..job.nodes[1].port)

  print(rpc.call(job.nodes[1], {"call_me", job.position}))
  events.sleep(5)
  os.exit()
end)
