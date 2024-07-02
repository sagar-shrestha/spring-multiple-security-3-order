//package com.sagar.baseproject.controller.web;
//
//import com.sagar.baseproject.common.annotation.CustomWebController;
//import com.sagar.baseproject.common.pojo.response.GlobalApiResponse;
//import com.sagar.baseproject.service.TicketImageService;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.MediaType;
//import org.springframework.http.ResponseEntity;
//import org.springframework.stereotype.Controller;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PathVariable;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//import java.io.IOException;
//
//@CustomWebController
//@RequestMapping("rest/")
//@RequiredArgsConstructor
//public class TicketImageController {
//
//    private final TicketImageService ticketImageService;
//
////    @PreAuthorize("hasAnyRole('SUPER_ADMIN')")
//    @GetMapping(value = "getImageById/{id}", produces = MediaType.MULTIPART_MIXED_VALUE)
//    public ResponseEntity<?> getTicketImageById(@PathVariable("id") int imageId,
//                                                HttpServletResponse httpServletResponse) throws IOException {
//        ticketImageService.getTicketImageById(imageId, httpServletResponse);
//        return ResponseEntity.ok(GlobalApiResponse
//                .builder()
//                .code(HttpStatus.OK.value())
//                .data(null)
//                .message("Ticket Saved Successfully.")
//                .build());
//    }
//}
