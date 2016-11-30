var Utils = {
    ab2str: function (buffer) {
        var str = "";
        for (var iii = 0; iii < buffer.byteLength; iii++) {
            str += String.fromCharCode(buffer[iii]);
        }
        return str;
    },
    str2ab: function (str) {
        var arrBuff = new ArrayBuffer(str.length);
        var bytes = new Uint8Array(arrBuff);
        for (var iii = 0; iii < str.length; iii++) {
            bytes[iii] = str.charCodeAt(iii);
        }
        return bytes;
    }
};