function asyncHandler(RequestHandler) {
  return function (req, res, next) {
    Promise.resolve(RequestHandler(req, res, next)).catch(function (err) {
      next(err);
    });
  };
}

export { asyncHandler };
