::  nockup basic scaffold + vesl graft markers.
::
::  Copy this file over your nockup project's hoon/app/app.hoon,
::  then run `graft-inject hoon/app/app.hoon` to wire in the graft.
::  The `::  nockup:*` comments are injection anchors — don't delete them
::  until after you run graft-inject.
::
/+  lib
::  nockup:imports
/=  *  /common/wrapper
::
=>
|%
+$  versioned-state
  $:  %v1
      ::  nockup:state
  ==
::
::  effect is `*` so grafted vesl-effects pass through without molding.
::  constrain this yourself once you know your domain's effect shape.
::
+$  effect  *
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
|%
++  moat  (keep versioned-state)
::
++  inner
  |_  state=versioned-state
  ::
  ++  load
    |=  old-state=versioned-state
    ^-  _state
    ?:  =(-.old-state %v1)
      old-state
    old-state
  ::
  ++  peek
    |=  =path
    ^-  (unit (unit *))
    ::  nockup:peek
    ~
  ::
  ++  poke
    |=  =ovum:moat
    ^-  [(list effect) _state]
    =/  act  ((soft cause) cause.input.ovum)
    ?~  act
      ~>  %slog.[3 (crip "invalid cause {<cause.input.ovum>}")]
      :_  state
      ^-  (list effect)
      ~[[%effect 'Invalid cause format']]
    ::  nockup:poke-prelude
    =/  out=[efx=(list effect) new=_state]
      ?-    -.u.act
          %cause
        ~>  %slog.[1 'poked']
        [~ state]
        ::  nockup:poke
      ==
    ::  nockup:poke-postlude
    out
  --
--
((moat |) inner)
