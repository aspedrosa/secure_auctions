# Secure Auctions

Project of the class "Information and Organizational Security"
  (first semester, second year, Software Engineering,
  [UA](https://www.ua.pt))

We had to make a **SECURE** system where clients could create
  auctions, make bids to them and see the contents (bids, winner,
  creation info) of open or closed auctions.

Full description of what was evaluated on the file `assigment.pdf`.

Full description of the security mechanisms, how the several
  entities were implemented and the flow of the several processes
  on the file `report.pdf`.

## Issues

### Security issues

Functionalities that were mandatory to implement:

- The output of the dynamic code set by the creator of the auction
  is not checked by the client. Both servers can manipulate
  fields associated
- The client doesn't verify if the certificate on the "manager
  validation" field of a block belongs to the manager. A client
  certificate can be used, as the user can validate it and will
  say that the certificate is valid. Although, the signature, also
  on the "manager validation", will be invalid

### Implementation issues

Issues that we have on our system but were not mandatory to solve
  them:

- Exception handling not perfect
- Because there is multithread on the repository, synchronization
  mechanisms are needed (semaphores). As a consequence of the
  above item, whenever a thread fails the synchronization mechanisms
  are not released leading to a dead lock on the repository
- A server only accepts a connection at a time (entities will
  fail if they try to connect to a busy server)
- Remote code execution on the servers (Only confinement mandatory)
- Comments on code :sweat_smile:
  
## Team

  Me  
  Duarte Castanho [@duartecastanho](https://github.com/duartecastanho)
