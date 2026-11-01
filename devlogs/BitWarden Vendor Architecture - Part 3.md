# BitWarden Vendor Architecture - Part 3
Making the orchestrator is pretty difficult because tying everything together is soo difficult, especially with the attachment stuff. BitWarden has some weird concepts on how it works. When creating an item and pushing it to the server, the server generates the id for you and sends the whole cipher back. However, if the network request fails halfway through, then it can create it online, without giving you the id. There are 3 solutions to this. One, is to just re-push, which creates a duplicate. Another way to fix this, is to leave it and fail, which is not a good idea. The best way to combat this situation, is to pull the items from the server, and find the one that was created by comparing the key from the local and remote vaults. The issue, is that sometimes, there is no key, so we have to rely on comparing the fields alone, which isnt the best, but its the only way. This is pretty difficult to think of on the spot and to resolve quickly, so thats why it took me so long. The other issue, is that I've faced a roadblock. I didnt think of attachments when designing the runtime class, so I have to add more funcs to help with offline attachments. Another issue, is that the runtime class is getting kinda messy now, since there are like 5 of the same type of funcs so I have to clean that up too. And then, I have the largest issue that I have to fix. Syncing. Syncing is a pretty weird concept on BitWarden. If you update an item offline, you dont change the revision Date, the version changes it. However, if the server's item was changed as well, then it gets complicated because you need to handle it yourself. The first thing you can do, is to merge the individual fields, like if the name was changed on the server, and the username was changed on the client, then merge both. However if the name was changed on the server and the client, then you can create a new item with (conflict X) and then push that. All this is pretty complicated, and its probably going to get even more complicated soon.

To solve this, we can have a json thing that stores the uuids of all the created, partial creation and deleted items, folders and attachments and also have a json array with a copy of the old item, attachment and folder bodies.
We can also have a new field called localRevisionDate which holds the localRevisionDate. We can also have a new field called VaultType which just holds server or local.
At sync time, we must:
 - check online vault if the partial creation items already exist
 - upload offline created items to the remote
 - upload offline updated items to the remove
   - resolve if necessary
 - remove offline deleted items from remote
 - push offline attachments
 - pull items from the server which have an id which doesnt exist offline (only after we check the vault if the partial creation items exist)
 - if revision date is newer:
   - item was updated on the server, so pull, fix conflicts
 - if revision date is older:
   - warn the user
 - if the item id isnt in created offline items, and the item doesnt exist on server:
   - delete from local

We should also have a shared logger, to propagate errors from the backend to the UI. - Create logger class