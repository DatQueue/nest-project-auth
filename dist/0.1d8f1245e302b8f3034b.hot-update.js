"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 121:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtAccessAuthGuard = void 0;
const common_1 = __webpack_require__(6);
const jwt_1 = __webpack_require__(50);
const passport_1 = __webpack_require__(23);
let JwtAccessAuthGuard = class JwtAccessAuthGuard extends (0, passport_1.AuthGuard)('jwt-access-token') {
    constructor(jwtService) {
        super();
        this.jwtService = jwtService;
    }
    canActivate(context) {
        try {
            const request = context.switchToHttp().getRequest();
            let access_token = request.cookies['access_token'];
            const decoded = this.jwtService.verify(access_token);
            console.log(decoded.exp);
            return this.jwtService.verify(access_token);
        }
        catch (err) {
            return false;
        }
    }
};
JwtAccessAuthGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _a : Object])
], JwtAccessAuthGuard);
exports.JwtAccessAuthGuard = JwtAccessAuthGuard;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("21aa963dde6e42b228d2")
/******/ })();
/******/ 
/******/ }
;