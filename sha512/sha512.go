

  @override
  Future<Uint8List> sha512(List<int> data) {
    Completer<ByteBuffer> completer = new Completer();
    
    JsObject promise = _kevalin.callMethod('digest', [
      new JsObject.jsify({'name': SHA_512}),
      new Uint8List.fromList(data)
    ]);
    
    promise.callMethod('then', [
      (Uint8List buffer) {
        completer.complete(buffer);
      },
      completer.completeError
    ]);
    
    return completer.future;
  }