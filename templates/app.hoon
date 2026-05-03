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
::  domain-effect is your app's effect union. Add variants here as
::  your app emits them. The codegen-generated `+$ effect` below
::  splats domain-effect into a typed union with all graft effects.
::
::  nockup:domain-effect
+$  domain-effect
  $%  [%domain-placeholder ~]
  ==
::
::  graft-inject codegen replaces the open `+$ effect *` below with a
::  typed union. Do not edit the codegen banner block by hand.
::
::  nockup:effect-union
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
      [~ state]
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
